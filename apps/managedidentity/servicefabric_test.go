// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/storage"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

func TestServiceFabricAcquireTokenReturnsTokenSuccess(t *testing.T) {
	setEnvVars(t, ServiceFabric)
	testCases := []struct {
		resource string
		miType   ID
	}{
		{resource: resource, miType: SystemAssigned()},
		{resource: resourceDefaultSuffix, miType: SystemAssigned()},
	}
	for _, testCase := range testCases {
		t.Run(string(DefaultToIMDS)+"-"+testCase.miType.value(), func(t *testing.T) {
			endpoint := imdsDefaultEndpoint
			var localUrl *url.URL
			var localHeader http.Header
			mockClient := mock.NewClient()
			responseBody, err := getSuccessfulResponse(resource, true)
			if err != nil {
				t.Fatalf(errorFormingJsonResponse, err.Error())
			}

			mockClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusOK), mock.WithBody(responseBody), mock.WithCallback(func(r *http.Request) {
				localUrl = r.URL
				localHeader = r.Header
			}))
			// resetting cache
			before := cacheManager
			defer func() { cacheManager = before }()
			cacheManager = storage.New(nil)

			client, err := New(testCase.miType, WithHTTPClient(mockClient))
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.AcquireToken(context.Background(), testCase.resource)
			if err != nil {
				t.Fatal(err)
			}
			if localUrl == nil || !strings.HasPrefix(localUrl.String(), "http://localhost:40342/metadata/identity/oauth2/token") {
				t.Fatalf("url request is not on %s got %s", endpoint, localUrl)
			}
			query := localUrl.Query()

			if got := query.Get(apiVersionQueryParameterName); got != serviceFabricAPIVersion {
				t.Fatalf("api-version not on %s got %s", serviceFabricAPIVersion, got)
			}
			if query.Get(resourceQueryParameterName) != strings.TrimSuffix(testCase.resource, "/.default") {
				t.Fatal("suffix /.default was not removed.")
			}
			if localHeader.Get("Accept") != "application/json" {
				t.Fatalf("expected Accept header to be application/json, got %s", localHeader.Get("Accept"))
			}
			if localHeader.Get("Secret") != "secret" {
				t.Fatalf("expected secret to be secret, got %s", query.Get("Secret"))
			}
			if result.Metadata.TokenSource != base.TokenSourceIdentityProvider {
				t.Fatalf("expected IndenityProvider tokensource, got %d", result.Metadata.TokenSource)
			}
			if result.AccessToken != token {
				t.Fatalf("wanted %q, got %q", token, result.AccessToken)
			}
			result, err = client.AcquireToken(context.Background(), testCase.resource)
			if err != nil {
				t.Fatal(err)
			}
			if result.Metadata.TokenSource != base.TokenSourceCache {
				t.Fatalf("wanted cache token source, got %d", result.Metadata.TokenSource)
			}
			secondFakeClient, err := New(testCase.miType, WithHTTPClient(mockClient))
			if err != nil {
				t.Fatal(err)
			}
			result, err = secondFakeClient.AcquireToken(context.Background(), testCase.resource)
			if err != nil {
				t.Fatal(err)
			}
			if result.Metadata.TokenSource != base.TokenSourceCache {
				t.Fatalf("cache result wanted cache token source, got %d", result.Metadata.TokenSource)
			}
		})
	}
}

// TestAppServiceWithClaimsAndBadAccessToken tests the scenario where claims are passed
// and a bad access token is retrieved from the cache
func TestServiceFabricWithClaimsAndBadAccessToken(t *testing.T) {
	setEnvVars(t, ServiceFabric)
	localUrl := &url.URL{}
	mockClient := mock.NewClient()
	// Second response is a successful token response after retrying with claims
	responseBody, err := getSuccessfulResponse(resource, false)
	if err != nil {
		t.Fatalf(errorFormingJsonResponse, err.Error())
	}
	mockClient.AppendResponse(
		mock.WithHTTPStatusCode(http.StatusOK),
		mock.WithBody(responseBody),
	)
	mockClient.AppendResponse(
		mock.WithHTTPStatusCode(http.StatusOK),
		mock.WithBody(responseBody),
		mock.WithCallback(func(r *http.Request) {
			localUrl = r.URL
		}))
	// Reset cache for clean test
	before := cacheManager
	defer func() { cacheManager = before }()
	cacheManager = storage.New(nil)

	client, err := New(SystemAssigned(),
		WithHTTPClient(mockClient),
		WithClientCapabilities([]string{"c1", "c2"}))
	if err != nil {
		t.Fatal(err)
	}

	// Call AcquireToken which should trigger token revocation flow
	result, err := client.AcquireToken(context.Background(), resource)
	if err != nil {
		t.Fatalf("AcquireToken failed: %v", err)
	}

	// Verify token was obtained successfully
	if result.AccessToken != token {
		t.Fatalf("Expected access token %q, got %q", token, result.AccessToken)
	}

	// Call AcquireToken which should trigger token revocation flow
	result, err = client.AcquireToken(context.Background(), resource, WithClaims("dummyClaims"))
	if err != nil {
		t.Fatalf("AcquireToken failed: %v", err)
	}

	localUrlQuerry := localUrl.Query()

	if localUrlQuerry.Get(apiVersionQueryParameterName) != serviceFabricAPIVersion {
		t.Fatalf("api-version not on %s got %s", serviceFabricAPIVersion, localUrlQuerry.Get(apiVersionQueryParameterName))
	}
	if r := localUrlQuerry.Get(resourceQueryParameterName); strings.HasSuffix(r, "/.default") {
		t.Fatal("suffix /.default was not removed.")
	}
	if localUrlQuerry.Get("xms_cc") != "c1,c2" {
		t.Fatalf("Expected client capabilities %q, got %q", "c1,c2", localUrlQuerry.Get("xms_cc"))
	}
	hash := sha256.Sum256([]byte(token))
	if localUrlQuerry.Get("token_sha256_to_refresh") != hex.EncodeToString(hash[:]) {
		t.Fatalf("Expected token_sha256_to_refresh %q, got %q", hex.EncodeToString(hash[:]), localUrlQuerry.Get("token_sha256_to_refresh"))
	}
	// Verify token was obtained successfully
	if result.AccessToken != token {
		t.Fatalf("Expected access token %q, got %q", token, result.AccessToken)
	}
}

func TestServiceFabricErrors(t *testing.T) {
	setEnvVars(t, ServiceFabric)
	mockClient := mock.NewClient()

	for _, testCase := range []ID{
		UserAssignedObjectID("ObjectId"),
		UserAssignedResourceID("resourceid"),
		UserAssignedClientID("ClientID")} {
		_, err := New(testCase, WithHTTPClient(mockClient))
		if err == nil {
			t.Fatal("expected error: Service Fabric API doesn't support specifying a user-assigned identity. The identity is determined by cluster resource configuration. See https://aka.ms/servicefabricmi")
		}
		if err.Error() != "Service Fabric API doesn't support specifying a user-assigned identity. The identity is determined by cluster resource configuration. See https://aka.ms/servicefabricmi" {
			t.Fatalf("expected error: Service Fabric API doesn't support specifying a user-assigned identity. The identity is determined by cluster resource configuration. See https://aka.ms/servicefabricmi, got error: %q", err)
		}

	}
}
