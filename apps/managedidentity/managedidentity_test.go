// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package managedidentity

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
)

func fakeMIClient(mangedIdentityId ID, options ...ClientOption) (Client, error) {
	fakeClient, err := New(mangedIdentityId, options...)

	if err != nil {
		return Client{}, err
	}

	return fakeClient, nil
}

type errorClient struct{}

func (*errorClient) CloseIdleConnections() {}
func (*errorClient) Do(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("expected no requests but received one for %s", req.URL.String())
}

type FakeClient struct {
	responseType int
}

func (c *FakeClient) CloseIdleConnections() {}
func (c *FakeClient) Do(req *http.Request) (*http.Response, error) {
	println(c.responseType)
	w := makeResponse(c.responseType)
	return &w, nil
}

func makeResponse(responseType int) http.Response {
	if responseType == 1 {
		return http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(`{
      "access_token": "fakeToken",
      "refresh_token": "",
      "expires_in": "3599",
      "expires_on": "1506484173",
      "not_before": "1506480273",
      "token_type": "Bearer"
    }`)),
			Header: make(http.Header),
		}
	} else {
		return http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(strings.NewReader(`{}`)),
			Header:     make(http.Header),
		}
	}
}
func TestManagedIdentityIMDS_SAMISuccess(t *testing.T) {
	fakeHTTPClient := FakeClient{responseType: 1}

	client, err := fakeMIClient(SystemAssigned(), WithHTTPClient(&fakeHTTPClient))

	if err != nil {
		t.Fatal(err)
	}

	result, err := client.AcquireToken(context.Background(), "fakeresource")

	if err != nil {
		t.Fatal("TestManagedIdentity: unexpected nil error from TestManagedIdentity")
	}

	expected := accesstokens.TokenResponse{
		AccessToken:  "fakeToken",
		ExpiresOn:    internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
		ExtExpiresOn: internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
		TokenType:    "Bearer",
	}
	if result.AccessToken != expected.AccessToken {
		t.Fatalf(`unexpected access token "%s"`, result.AccessToken)
	}

}

func TestCreateIMDSAuthRequest(t *testing.T) {
	tests := []struct {
		name     string
		id       ID
		resource string
		claims   string
		wantErr  bool
	}{
		{
			name:     "System Assigned",
			id:       SystemAssigned(),
			resource: "https://management.azure.com",
			claims:   "",
			wantErr:  false,
		},
		{
			name:     "System Assigned",
			id:       SystemAssigned(),
			resource: "https://management.azure.com/.default",
			claims:   "",
			wantErr:  false,
		},
		{
			name:     "Client ID",
			id:       ClientID("test-client-id"),
			resource: "https://storage.azure.com",
			claims:   "",
			wantErr:  false,
		},
		{
			name:     "Resource ID",
			id:       ResourceID("test-resource-id"),
			resource: "https://vault.azure.net",
			claims:   "",
			wantErr:  false,
		},
		{
			name:     "Object ID",
			id:       ObjectID("test-object-id"),
			resource: "https://graph.microsoft.com",
			claims:   "",
			wantErr:  false,
		},
		{
			name:     "With Claims",
			id:       SystemAssigned(),
			resource: "https://management.azure.com",
			claims:   "test-claims",
			wantErr:  false,
		},
		{
			name:     "Empty Client ID",
			id:       ClientID(""),
			resource: "https://management.azure.com",
			claims:   "",
			wantErr:  true,
		},
		{
			name:     "Empty Resource ID",
			id:       ResourceID(""),
			resource: "https://management.azure.com",
			claims:   "",
			wantErr:  true,
		},
		{
			name:     "Empty Object ID",
			id:       ObjectID(""),
			resource: "https://management.azure.com",
			claims:   "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := createIMDSAuthRequest(context.Background(), tt.id, tt.resource, tt.claims)
			if tt.wantErr {
				if err == nil {
					t.Errorf("createIMDSAuthRequest() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("createIMDSAuthRequest() unexpected error = %v", err)
				return
			}

			if req == nil {
				t.Errorf("createIMDSAuthRequest() returned nil request")
				return
			}

			if req.Method != http.MethodGet {
				t.Errorf("createIMDSAuthRequest() method = %v, want %v", req.Method, http.MethodGet)
			}

			if !strings.HasPrefix(req.URL.String(), imdsEndpoint) {
				t.Errorf("createIMDSAuthRequest() URL = %v, want prefix %v", req.URL.String(), imdsEndpoint)
			}

			query := req.URL.Query()

			if query.Get(apiVersionQuerryParameterName) != "2018-02-01" {
				t.Errorf("createIMDSAuthRequest() api-version = %v, want %v", query.Get(apiVersionQuerryParameterName), "2018-02-01")
			}

			if query.Get(resourceQuerryParameterName) != removeSuffix(tt.resource, "/.default") {
				t.Errorf("createIMDSAuthRequest() resource = %v, want %v", query.Get(resourceQuerryParameterName), removeSuffix(tt.resource, "/.default"))
			}

			if tt.claims != "" && query.Get("claims") != tt.claims {
				t.Errorf("createIMDSAuthRequest() claims = %v, want %v", query.Get("claims"), tt.claims)
			}

			switch tt.id.(type) {
			case ClientID:
				if query.Get(miQuerryParameterClientId) != tt.id.value() {
					t.Errorf("createIMDSAuthRequest() client_id = %v, want %v", query.Get(miQuerryParameterClientId), tt.id.value())
				}
			case ResourceID:
				if query.Get(miQuerryParameterResourceId) != tt.id.value() {
					t.Errorf("createIMDSAuthRequest() msi_res_id = %v, want %v", query.Get(miQuerryParameterResourceId), tt.id.value())
				}
			case ObjectID:
				if query.Get(miQuerryParameterObjectId) != tt.id.value() {
					t.Errorf("createIMDSAuthRequest() object_id = %v, want %v", query.Get(miQuerryParameterObjectId), tt.id.value())
				}
			}
		})
	}
}

func TestManagedIdentityIMDS_SAMIHttpRequestFailure(t *testing.T) {
	fakeHTTPClient := FakeClient{responseType: 2}

	client, err := fakeMIClient(SystemAssigned(), WithHTTPClient(&fakeHTTPClient))

	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.AcquireToken(context.Background(), "fakeresource"); err == nil {
		t.Fatal("TestManagedIdentity: Should have returned error for incorrect http request.")
	}

}

func TestManagedIdentityIMDS_SAMIError(t *testing.T) {
	fakeHTTPClient := errorClient{}

	client, err := fakeMIClient(SystemAssigned(), WithHTTPClient(&fakeHTTPClient))

	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.AcquireToken(context.Background(), "fakeresource"); err == nil {
		t.Fatal("TestManagedIdentity: Should have returned error for incorrect http request.")
	}

}
