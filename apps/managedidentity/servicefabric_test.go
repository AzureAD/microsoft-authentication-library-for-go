// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/storage"
)

type serviceFabricCustomHTTPClient struct{}

func (serviceFabricCustomHTTPClient) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("not implemented")
}

func (serviceFabricCustomHTTPClient) CloseIdleConnections() {}

type serviceFabricRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f serviceFabricRoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestServiceFabricAcquireTokenWithPinnedCertificate(t *testing.T) {
	var requests int32
	var receivedRequest *http.Request
	responseBody, err := getSuccessfulResponse(resource, true)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		atomic.AddInt32(&requests, 1)
		receivedRequest = request.Clone(request.Context())
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(responseBody)
	}))
	defer server.Close()

	setServiceFabricEnvironment(t, server.URL, serviceFabricServerThumbprint(server))
	resetServiceFabricCache(t)

	client, err := New(SystemAssigned(), WithHTTPClient(server.Client()), WithRetryPolicyDisabled())
	if err != nil {
		t.Fatal(err)
	}
	var changedEndpointRequests int32
	changedEndpoint := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		atomic.AddInt32(&changedEndpointRequests, 1)
		if request.Header.Get("Secret") != "" {
			t.Error("Secret was sent after IDENTITY_ENDPOINT changed")
		}
		response.WriteHeader(http.StatusInternalServerError)
	}))
	defer changedEndpoint.Close()
	t.Setenv(identityEndpointEnvVar, changedEndpoint.URL)

	result, err := client.AcquireToken(context.Background(), resourceDefaultSuffix)
	if err != nil {
		t.Fatal(err)
	}
	if receivedRequest == nil {
		t.Fatal("expected Service Fabric request")
	}
	if receivedRequest.URL.Query().Get(apiVersionQueryParameterName) != serviceFabricAPIVersion {
		t.Fatalf("expected api version %q", serviceFabricAPIVersion)
	}
	if receivedRequest.URL.Query().Get(resourceQueryParameterName) != resource {
		t.Fatalf("expected resource %q", resource)
	}
	if receivedRequest.Header.Get("Accept") != "application/json" {
		t.Fatalf("expected Accept header to be application/json, got %q", receivedRequest.Header.Get("Accept"))
	}
	if receivedRequest.Header.Get("Secret") != "secret" {
		t.Fatalf("expected Secret header to be set, got %q", receivedRequest.Header.Get("Secret"))
	}
	if result.Metadata.TokenSource != base.TokenSourceIdentityProvider {
		t.Fatalf("expected identity provider token source, got %d", result.Metadata.TokenSource)
	}
	if result.AccessToken != token {
		t.Fatalf("wanted %q, got %q", token, result.AccessToken)
	}

	result, err = client.AcquireToken(context.Background(), resource)
	if err != nil {
		t.Fatal(err)
	}
	if result.Metadata.TokenSource != base.TokenSourceCache {
		t.Fatalf("expected cache token source, got %d", result.Metadata.TokenSource)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("expected one Service Fabric request, got %d", got)
	}
	if got := atomic.LoadInt32(&changedEndpointRequests); got != 0 {
		t.Fatalf("expected no request to changed endpoint, got %d", got)
	}
}

func TestServiceFabricRejectsMismatchedCertificateBeforeRequest(t *testing.T) {
	var requests int32
	var receivedSecret string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		atomic.AddInt32(&requests, 1)
		receivedSecret = request.Header.Get("Secret")
		response.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	setServiceFabricEnvironment(t, server.URL, strings.Repeat("0", 40))
	resetServiceFabricCache(t)

	client, err := New(SystemAssigned(), WithHTTPClient(server.Client()), WithRetryPolicyDisabled())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AcquireToken(context.Background(), resource)
	if err == nil {
		t.Fatal("expected a thumbprint validation error")
	}
	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Fatalf("expected no HTTP request after a thumbprint mismatch, got %d", got)
	}
	if receivedSecret != "" {
		t.Fatalf("expected no Secret to be transmitted, got %q", receivedSecret)
	}
}

func TestServiceFabricDerivedClientPreservesCallerConfiguration(t *testing.T) {
	responseBody, err := getSuccessfulResponse(resource, true)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(responseBody)
	}))
	defer server.Close()

	setServiceFabricEnvironment(t, server.URL, serviceFabricServerThumbprint(server))
	resetServiceFabricCache(t)

	callerTransport := server.Client().Transport.(*http.Transport).Clone()
	callerTLSConfig := callerTransport.TLSClientConfig.Clone()
	callerTLSConfig.MinVersion = tls.VersionTLS12
	callerTLSConfig.ServerName = "caller.example"
	callerTransport.TLSClientConfig = callerTLSConfig
	callerTransport.MaxIdleConns = 17
	callerTransport.ResponseHeaderTimeout = 3 * time.Second
	callerClient := &http.Client{
		Transport: callerTransport,
		Timeout:   4 * time.Second,
	}

	client, err := New(SystemAssigned(), WithHTTPClient(callerClient), WithRetryPolicyDisabled())
	if err != nil {
		t.Fatal(err)
	}
	derivedClient, ok := client.httpClient.(*http.Client)
	if !ok {
		t.Fatalf("expected derived *http.Client, got %T", client.httpClient)
	}
	if derivedClient == callerClient {
		t.Fatal("Service Fabric client must not reuse the caller client")
	}
	if derivedClient.Timeout != callerClient.Timeout {
		t.Fatalf("expected timeout %v, got %v", callerClient.Timeout, derivedClient.Timeout)
	}
	derivedTransport, ok := derivedClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected derived *http.Transport, got %T", derivedClient.Transport)
	}
	if derivedTransport == callerTransport {
		t.Fatal("Service Fabric client must not reuse the caller transport")
	}
	if derivedTransport.MaxIdleConns != callerTransport.MaxIdleConns {
		t.Fatalf("expected MaxIdleConns %d, got %d", callerTransport.MaxIdleConns, derivedTransport.MaxIdleConns)
	}
	if derivedTransport.ResponseHeaderTimeout != callerTransport.ResponseHeaderTimeout {
		t.Fatalf("expected ResponseHeaderTimeout %v, got %v", callerTransport.ResponseHeaderTimeout, derivedTransport.ResponseHeaderTimeout)
	}
	if derivedTransport.TLSClientConfig == callerTLSConfig {
		t.Fatal("Service Fabric client must not reuse the caller TLS config")
	}
	if derivedTransport.TLSClientConfig.MinVersion != callerTLSConfig.MinVersion {
		t.Fatalf("expected TLS minimum version %d, got %d", callerTLSConfig.MinVersion, derivedTransport.TLSClientConfig.MinVersion)
	}
	if derivedTransport.TLSClientConfig.ServerName != callerTLSConfig.ServerName {
		t.Fatalf("expected TLS server name %q, got %q", callerTLSConfig.ServerName, derivedTransport.TLSClientConfig.ServerName)
	}
	if callerTLSConfig.InsecureSkipVerify {
		t.Fatal("caller TLS config was modified")
	}

	if derivedTransport.TLSClientConfig.VerifyConnection == nil {
		t.Fatal("expected Service Fabric TLS verification callback")
	}
	if _, err = client.AcquireToken(context.Background(), resource); err != nil {
		t.Fatal(err)
	}
}

func TestServiceFabricRejectsUnsupportedClientsAndEndpoints(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	validThumbprint := serviceFabricServerThumbprint(server)

	t.Run("HTTP endpoint", func(t *testing.T) {
		setServiceFabricEnvironment(t, strings.Replace(server.URL, "https://", "http://", 1), validThumbprint)
		_, err := New(SystemAssigned(), WithHTTPClient(server.Client()))
		if err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
			t.Fatalf("expected HTTPS endpoint error, got %v", err)
		}
	})
	t.Run("invalid thumbprint", func(t *testing.T) {
		setServiceFabricEnvironment(t, server.URL, "not-a-thumbprint")
		_, err := New(SystemAssigned(), WithHTTPClient(server.Client()))
		if err == nil || !strings.Contains(err.Error(), identityServerThumbprintEnvVar) {
			t.Fatalf("expected thumbprint error, got %v", err)
		}
	})
	t.Run("custom HTTP client", func(t *testing.T) {
		setServiceFabricEnvironment(t, server.URL, validThumbprint)
		_, err := New(SystemAssigned(), WithHTTPClient(serviceFabricCustomHTTPClient{}))
		if err == nil || !strings.Contains(err.Error(), "*http.Client") {
			t.Fatalf("expected standard client error, got %v", err)
		}
	})
	t.Run("custom transport", func(t *testing.T) {
		setServiceFabricEnvironment(t, server.URL, validThumbprint)
		customClient := &http.Client{Transport: serviceFabricRoundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("not implemented")
		})}
		_, err := New(SystemAssigned(), WithHTTPClient(customClient))
		if err == nil || !strings.Contains(err.Error(), "*http.Transport") {
			t.Fatalf("expected standard transport error, got %v", err)
		}
	})
	t.Run("custom TLS dialer", func(t *testing.T) {
		setServiceFabricEnvironment(t, server.URL, validThumbprint)
		customTransport := server.Client().Transport.(*http.Transport).Clone()
		customTransport.DialTLSContext = func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("not implemented")
		}
		_, err := New(SystemAssigned(), WithHTTPClient(&http.Client{Transport: customTransport}))
		if err == nil || !strings.Contains(err.Error(), "custom TLS dialing") {
			t.Fatalf("expected custom TLS dialer error, got %v", err)
		}
	})
	t.Run("custom TLS verification", func(t *testing.T) {
		setServiceFabricEnvironment(t, server.URL, validThumbprint)
		customTransport := server.Client().Transport.(*http.Transport).Clone()
		customTransport.TLSClientConfig = customTransport.TLSClientConfig.Clone()
		customTransport.TLSClientConfig.VerifyConnection = func(tls.ConnectionState) error { return nil }
		_, err := New(SystemAssigned(), WithHTTPClient(&http.Client{Transport: customTransport}))
		if err == nil || !strings.Contains(err.Error(), "custom TLS verification") {
			t.Fatalf("expected custom TLS verification error, got %v", err)
		}
	})
	t.Run("custom TLS protocol handler", func(t *testing.T) {
		setServiceFabricEnvironment(t, server.URL, validThumbprint)
		customTransport := server.Client().Transport.(*http.Transport).Clone()
		customTransport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		_, err := New(SystemAssigned(), WithHTTPClient(&http.Client{Transport: customTransport}))
		if err == nil || !strings.Contains(err.Error(), "custom TLS protocol handlers") {
			t.Fatalf("expected custom TLS protocol handler error, got %v", err)
		}
	})
}

func TestServiceFabricRejectsHTTPRedirectBeforeSendingSecret(t *testing.T) {
	var redirectedRequests int32
	var redirectedSecret string
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		atomic.AddInt32(&redirectedRequests, 1)
		redirectedSecret = request.Header.Get("Secret")
		response.WriteHeader(http.StatusInternalServerError)
	}))
	defer redirectTarget.Close()

	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, redirectTarget.URL, http.StatusFound)
	}))
	defer server.Close()
	setServiceFabricEnvironment(t, server.URL, serviceFabricServerThumbprint(server))
	resetServiceFabricCache(t)

	client, err := New(SystemAssigned(), WithHTTPClient(server.Client()), WithRetryPolicyDisabled())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AcquireToken(context.Background(), resource)
	if err == nil || !strings.Contains(err.Error(), "redirects are not permitted") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
	if got := atomic.LoadInt32(&redirectedRequests); got != 0 {
		t.Fatalf("expected no HTTP redirect request, got %d", got)
	}
	if redirectedSecret != "" {
		t.Fatalf("expected no Secret on HTTP redirect, got %q", redirectedSecret)
	}
}

func TestServiceFabricLeavesCustomClientAvailableToOtherSources(t *testing.T) {
	t.Setenv(identityEndpointEnvVar, "")
	t.Setenv(identityHeaderEnvVar, "")
	t.Setenv(identityServerThumbprintEnvVar, "")
	t.Setenv(msiEndpointEnvVar, "")
	t.Setenv(msiSecretEnvVar, "")
	t.Setenv(imdsEndVar, "")
	customClient := serviceFabricCustomHTTPClient{}

	client, err := New(SystemAssigned(), WithHTTPClient(customClient))
	if err != nil {
		t.Fatal(err)
	}
	if client.httpClient != customClient {
		t.Fatal("non-Service Fabric clients must not be changed")
	}
}

func TestServiceFabricErrors(t *testing.T) {
	setEnvVars(t, ServiceFabric)
	customClient := serviceFabricCustomHTTPClient{}

	for _, testCase := range []ID{
		UserAssignedObjectID("ObjectId"),
		UserAssignedResourceID("resourceid"),
		UserAssignedClientID("ClientID"),
	} {
		_, err := New(testCase, WithHTTPClient(customClient))
		if err == nil {
			t.Fatal("expected Service Fabric user-assigned identity error")
		}
		if err.Error() != "Service Fabric API doesn't support specifying a user-assigned identity. The identity is determined by cluster resource configuration. See https://aka.ms/servicefabricmi" {
			t.Fatalf("unexpected error: %q", err)
		}
	}
}

func setServiceFabricEnvironment(t *testing.T, endpoint, thumbprint string) {
	t.Helper()
	t.Setenv(identityEndpointEnvVar, endpoint)
	t.Setenv(identityHeaderEnvVar, "secret")
	t.Setenv(identityServerThumbprintEnvVar, thumbprint)
	t.Setenv(msiEndpointEnvVar, "")
	t.Setenv(msiSecretEnvVar, "")
	t.Setenv(imdsEndVar, "")
}

func resetServiceFabricCache(t *testing.T) {
	t.Helper()
	originalCacheManager := cacheManager
	cacheManager = storage.New(nil)
	t.Cleanup(func() { cacheManager = originalCacheManager })
}

func serviceFabricServerThumbprint(server *httptest.Server) string {
	thumbprint := sha1.Sum(server.Certificate().Raw) // #nosec G401 -- Service Fabric uses SHA-1 thumbprints.
	return hex.EncodeToString(thumbprint[:])
}
