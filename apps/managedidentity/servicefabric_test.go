// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto/sha1" // #nosec G505 -- Service Fabric defines certificate thumbprints as SHA-1.
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/storage"
	"golang.org/x/net/http2"
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

// serviceFabricConfigurableClient is a ClientConfigurer that supplies a base client to augment
// and routes requests through the augmented client, mimicking a caller that wraps its own transport.
type serviceFabricConfigurableClient struct {
	base           *http.Client
	configured     *http.Client
	configureCalls int
}

func (c *serviceFabricConfigurableClient) Do(request *http.Request) (*http.Response, error) {
	if c.configured == nil {
		return nil, errors.New("transport was not configured")
	}
	// Inject observable middleware so tests can confirm requests traverse the wrapper.
	request.Header.Set("X-Configurable-Middleware", "wrapped")
	return c.configured.Do(request)
}

func (c *serviceFabricConfigurableClient) CloseIdleConnections() {
	if c.configured != nil {
		c.configured.CloseIdleConnections()
	}
}

func (c *serviceFabricConfigurableClient) ConfigureClient(augment func(*http.Client) (*http.Client, error)) error {
	c.configureCalls++
	configured, err := augment(c.base)
	if err != nil {
		return err
	}
	c.configured = configured
	return nil
}

var _ ClientConfigurer = (*serviceFabricConfigurableClient)(nil)

func TestServiceFabricWithClientConfigurer(t *testing.T) {
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

	configurable := &serviceFabricConfigurableClient{base: server.Client()}
	client, err := New(SystemAssigned(), WithHTTPClient(configurable), WithRetryPolicyDisabled())
	if err != nil {
		t.Fatal(err)
	}
	if configurable.configureCalls != 1 {
		t.Fatalf("expected ConfigureClient to be called once, got %d", configurable.configureCalls)
	}
	if configurable.configured == nil {
		t.Fatal("expected ConfigureClient to install an augmented client")
	}
	if configurable.configured == configurable.base {
		t.Fatal("expected augment to derive a new client rather than reuse the base")
	}
	// The configurer, not the derived client, must remain in use so its middleware is preserved.
	if client.httpClient != configurable {
		t.Fatalf("expected the configurable client to remain in use, got %T", client.httpClient)
	}
	derivedTransport, ok := configurable.configured.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected derived *http.Transport, got %T", configurable.configured.Transport)
	}
	if derivedTransport.TLSClientConfig == nil || derivedTransport.TLSClientConfig.VerifyConnection == nil {
		t.Fatal("expected Service Fabric certificate pinning on the derived transport")
	}
	if configurable.configured.CheckRedirect == nil {
		t.Fatal("expected Service Fabric redirect policy on the derived client")
	}

	result, err := client.AcquireToken(context.Background(), resource)
	if err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("expected one Service Fabric request, got %d", got)
	}
	if receivedRequest == nil {
		t.Fatal("expected Service Fabric request")
	}
	if receivedRequest.Header.Get("Secret") != "secret" {
		t.Fatalf("expected Secret header to be set, got %q", receivedRequest.Header.Get("Secret"))
	}
	if receivedRequest.Header.Get("X-Configurable-Middleware") != "wrapped" {
		t.Fatalf("expected wrapper middleware header to reach the server, got %q", receivedRequest.Header.Get("X-Configurable-Middleware"))
	}
	if result.AccessToken != token {
		t.Fatalf("wanted %q, got %q", token, result.AccessToken)
	}
}

// serviceFabricFailingConfigurableClient is a ClientConfigurer whose ConfigureClient reports a
// configuration error, so New must fail closed rather than return a partially configured client.
type serviceFabricFailingConfigurableClient struct {
	err            error
	configureCalls int
}

func (c *serviceFabricFailingConfigurableClient) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("transport was not configured")
}

func (c *serviceFabricFailingConfigurableClient) CloseIdleConnections() {}

func (c *serviceFabricFailingConfigurableClient) ConfigureClient(augment func(*http.Client) (*http.Client, error)) error {
	c.configureCalls++
	return c.err
}

var _ ClientConfigurer = (*serviceFabricFailingConfigurableClient)(nil)

// serviceFabricSwallowingConfigurableClient is a ClientConfigurer that calls augment, ignores the
// error augment reports, and returns nil. New must still fail closed rather than hand back a client
// that lacks the mandatory Service Fabric certificate pinning and redirect policy.
type serviceFabricSwallowingConfigurableClient struct {
	base           *http.Client
	configureCalls int
	augmentErr     error
}

func (c *serviceFabricSwallowingConfigurableClient) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("transport was not configured")
}

func (c *serviceFabricSwallowingConfigurableClient) CloseIdleConnections() {}

func (c *serviceFabricSwallowingConfigurableClient) ConfigureClient(augment func(*http.Client) (*http.Client, error)) error {
	c.configureCalls++
	_, c.augmentErr = augment(c.base)
	// Deliberately swallow the augment error and report success to MSAL.
	return nil
}

var _ ClientConfigurer = (*serviceFabricSwallowingConfigurableClient)(nil)

func TestServiceFabricClientConfigurerErrorFailsNew(t *testing.T) {
	t.Run("ConfigureClient propagates augment error", func(t *testing.T) {
		setServiceFabricEnvironment(t, "https://localhost", strings.Repeat("0", 40))
		resetServiceFabricCache(t)

		configureErr := errors.New("configuration failed")
		configurable := &serviceFabricFailingConfigurableClient{err: configureErr}
		_, err := New(SystemAssigned(), WithHTTPClient(configurable), WithRetryPolicyDisabled())
		if err == nil {
			t.Fatal("expected New to fail when ConfigureClient returns an error")
		}
		if !errors.Is(err, configureErr) {
			t.Fatalf("expected New to return the configuration error, got %v", err)
		}
		if configurable.configureCalls != 1 {
			t.Fatalf("expected ConfigureClient to be called once, got %d", configurable.configureCalls)
		}
	})

	t.Run("ConfigureClient swallows augment error", func(t *testing.T) {
		setServiceFabricEnvironment(t, "https://localhost", strings.Repeat("0", 40))
		resetServiceFabricCache(t)

		// Passing a nil base to augment makes serviceFabricCertificateVerifiedHTTPClient fail,
		// reproducing a configurer that ignores that error and reports success anyway.
		configurable := &serviceFabricSwallowingConfigurableClient{base: nil}
		_, err := New(SystemAssigned(), WithHTTPClient(configurable), WithRetryPolicyDisabled())
		if err == nil {
			t.Fatal("expected New to fail closed when augment fails even though ConfigureClient returned nil")
		}
		if configurable.configureCalls != 1 {
			t.Fatalf("expected ConfigureClient to be called once, got %d", configurable.configureCalls)
		}
		if configurable.augmentErr == nil {
			t.Fatal("expected augment to report an error for the nil base client")
		}
		if !errors.Is(err, configurable.augmentErr) {
			t.Fatalf("expected New to surface the augment error, got %v", err)
		}
	})
}

func TestServiceFabricConfigurableClientRejectsMismatchedCertificate(t *testing.T) {
	var requests int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		response.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	setServiceFabricEnvironment(t, server.URL, strings.Repeat("0", 40))
	resetServiceFabricCache(t)

	configurable := &serviceFabricConfigurableClient{base: server.Client()}
	client, err := New(SystemAssigned(), WithHTTPClient(configurable), WithRetryPolicyDisabled())
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
}

func TestServiceFabricConfigurableClientRejectsRedirectBeforeSendingSecret(t *testing.T) {
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

	configurable := &serviceFabricConfigurableClient{base: server.Client()}
	client, err := New(SystemAssigned(), WithHTTPClient(configurable), WithRetryPolicyDisabled())
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

// TestServiceFabricAcceptsConfiguredTLSNextProto guards against rejecting a non-nil TLSNextProto. A transport
// configured for HTTP/2 (e.g. via golang.org/x/net/http2.ConfigureTransports, as azure-sdk-for-go's default
// transport does) carries a non-nil TLSNextProto that Transport.Clone copies. Rejecting it would break those
// callers, and it is not a pinning-bypass vector because the transport completes the pinned TLS handshake
// before dispatching the connection to the ALPN handler.
func TestServiceFabricAcceptsConfiguredTLSNextProto(t *testing.T) {
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
	callerTransport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{
		"h2": func(string, *tls.Conn) http.RoundTripper { return nil },
	}
	callerClient := &http.Client{Transport: callerTransport}

	client, err := New(SystemAssigned(), WithHTTPClient(callerClient), WithRetryPolicyDisabled())
	if err != nil {
		t.Fatalf("expected a configured TLSNextProto to be accepted, got %v", err)
	}
	derivedClient, ok := client.httpClient.(*http.Client)
	if !ok {
		t.Fatalf("expected derived *http.Client, got %T", client.httpClient)
	}
	derivedTransport, ok := derivedClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected derived *http.Transport, got %T", derivedClient.Transport)
	}
	if derivedTransport.TLSClientConfig == nil || derivedTransport.TLSClientConfig.VerifyConnection == nil {
		t.Fatal("expected Service Fabric certificate pinning on the derived transport")
	}
	if _, err = client.AcquireToken(context.Background(), resource); err != nil {
		t.Fatal(err)
	}
}

// TestServiceFabricReusesHTTP2Transport exercises a transport that has actually served an HTTP/2 request, so
// its HTTP/2 state is genuinely populated rather than hand-assigned, then reuses it for Service Fabric and
// verifies that certificate pinning still holds for both a matching and a mismatched thumbprint.
func TestServiceFabricReusesHTTP2Transport(t *testing.T) {
	responseBody, err := getSuccessfulResponse(resource, true)
	if err != nil {
		t.Fatal(err)
	}
	var requests int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(responseBody)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	callerClient := server.Client()
	if _, ok := callerClient.Transport.(*http.Transport); !ok {
		t.Fatalf("expected *http.Transport from the test server client, got %T", callerClient.Transport)
	}
	// Exercise the transport so its HTTP/2 state is populated by a real request rather than hand-assigned.
	warmup, err := callerClient.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, warmup.Body)
	warmup.Body.Close()
	if warmup.ProtoMajor != 2 {
		t.Fatalf("expected the warm-up request to negotiate HTTP/2, got HTTP/%d.%d", warmup.ProtoMajor, warmup.ProtoMinor)
	}

	t.Run("matching pin succeeds", func(t *testing.T) {
		setServiceFabricEnvironment(t, server.URL, serviceFabricServerThumbprint(server))
		resetServiceFabricCache(t)

		client, err := New(SystemAssigned(), WithHTTPClient(callerClient), WithRetryPolicyDisabled())
		if err != nil {
			t.Fatalf("expected the reused HTTP/2 transport to be accepted, got %v", err)
		}
		before := atomic.LoadInt32(&requests)
		if _, err := client.AcquireToken(context.Background(), resource); err != nil {
			t.Fatal(err)
		}
		if got := atomic.LoadInt32(&requests) - before; got == 0 {
			t.Fatal("expected the pinned request to reach the server")
		}
	})

	t.Run("wrong pin fails", func(t *testing.T) {
		setServiceFabricEnvironment(t, server.URL, strings.Repeat("0", 40))
		resetServiceFabricCache(t)

		client, err := New(SystemAssigned(), WithHTTPClient(callerClient), WithRetryPolicyDisabled())
		if err != nil {
			t.Fatalf("expected the reused HTTP/2 transport to be accepted, got %v", err)
		}
		before := atomic.LoadInt32(&requests)
		if _, err := client.AcquireToken(context.Background(), resource); err == nil {
			t.Fatal("expected a thumbprint validation error")
		}
		if got := atomic.LoadInt32(&requests) - before; got != 0 {
			t.Fatalf("expected no HTTP request after a thumbprint mismatch, got %d", got)
		}
	})
}

// TestServiceFabricDoesNotReuseCallerHTTP2Connection reproduces the connection-reuse hazard from
// golang.org/x/net/http2.ConfigureTransports: its "h2" callback retains the caller's connection pool and
// Transport.Clone copies that callback by reference. A warm HTTP/2 connection to server A is established for a
// shared authority, later dials for that authority are routed to server B whose certificate matches the pin,
// and the Service Fabric request must reach the freshly pinned server B rather than reusing the pooled,
// unpinned connection to server A.
func TestServiceFabricDoesNotReuseCallerHTTP2Connection(t *testing.T) {
	responseBody, err := getSuccessfulResponse(resource, true)
	if err != nil {
		t.Fatal(err)
	}
	var warmedRequests, pinnedRequests int32
	// Server A answers the warm-up request and must never receive the pinned Service Fabric request.
	warmedServer := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&warmedRequests, 1)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(responseBody)
	}))
	warmedServer.EnableHTTP2 = true
	warmedServer.StartTLS()
	defer warmedServer.Close()

	// Server B holds the certificate whose thumbprint is pinned; the Service Fabric request must land here.
	pinnedServer := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&pinnedRequests, 1)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(responseBody)
	}))
	pinnedServer.EnableHTTP2 = true
	pinnedServer.StartTLS()
	defer pinnedServer.Close()

	// Dials for the single shared authority go to server A until the warm-up completes, then to server B.
	var routeToPinned atomic.Bool
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		addr := warmedServer.Listener.Addr().String()
		if routeToPinned.Load() {
			addr = pinnedServer.Listener.Addr().String()
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}

	callerTransport := &http.Transport{
		DialContext:       dial,
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- test transport; the derived client pins.
	}
	if _, err := http2.ConfigureTransports(callerTransport); err != nil {
		t.Fatal(err)
	}
	callerClient := &http.Client{Transport: callerTransport}

	const authority = "https://sf-pin.local:8443"
	// Warm an HTTP/2 connection to server A for the shared authority, populating the caller's pool.
	warmup, err := callerClient.Get(authority + "/")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, warmup.Body)
	warmup.Body.Close()
	if warmup.ProtoMajor != 2 {
		t.Fatalf("expected the warm-up request to negotiate HTTP/2, got HTTP/%d.%d", warmup.ProtoMajor, warmup.ProtoMinor)
	}
	if got := atomic.LoadInt32(&warmedRequests); got != 1 {
		t.Fatalf("expected the warm-up to reach server A once, got %d", got)
	}

	routeToPinned.Store(true)
	setServiceFabricEnvironment(t, authority, serviceFabricServerThumbprint(pinnedServer))
	resetServiceFabricCache(t)

	client, err := New(SystemAssigned(), WithHTTPClient(callerClient), WithRetryPolicyDisabled())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.AcquireToken(context.Background(), resource); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&warmedRequests); got != 1 {
		t.Fatalf("Service Fabric request reused the caller's pooled connection to server A (server A saw %d requests)", got)
	}
	if got := atomic.LoadInt32(&pinnedRequests); got == 0 {
		t.Fatal("expected the Service Fabric request to reach the pinned server B")
	}
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

func TestServiceFabricConfigurerIgnoredForOtherSources(t *testing.T) {
	t.Setenv(identityEndpointEnvVar, "")
	t.Setenv(identityHeaderEnvVar, "")
	t.Setenv(identityServerThumbprintEnvVar, "")
	t.Setenv(msiEndpointEnvVar, "")
	t.Setenv(msiSecretEnvVar, "")
	t.Setenv(imdsEndVar, "")

	// A ClientConfigurer is only consulted for Service Fabric; other sources must use it as a
	// plain ops.HTTPClient and never call ConfigureClient.
	configurable := &serviceFabricFailingConfigurableClient{err: errors.New("ConfigureClient should not be called")}
	client, err := New(SystemAssigned(), WithHTTPClient(configurable))
	if err != nil {
		t.Fatal(err)
	}
	if configurable.configureCalls != 0 {
		t.Fatalf("expected ConfigureClient not to be called for a non-Service Fabric source, got %d calls", configurable.configureCalls)
	}
	if client.httpClient != configurable {
		t.Fatal("non-Service Fabric clients must be used as-is")
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
