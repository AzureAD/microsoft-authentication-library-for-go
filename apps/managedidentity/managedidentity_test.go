// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package managedidentity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/storage"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

const (
	// test Resources
	resource              = "https://demo.azure.com"
	resourceDefaultSuffix = "https://demo.azure.com/.default"
	token                 = "fake-access-token"
)

type SuccessfulResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	Resource    string `json:"resource"`
	TokenType   string `json:"token_type"`
}

type ErrorRespone struct {
	Err  string `json:"error"`
	Desc string `json:"error_description"`
}

func getSuccessfulResponse(resource string) ([]byte, error) {
	duration := 10 * time.Minute
	expiresIn := duration.Seconds()
	response := SuccessfulResponse{
		AccessToken: token,
		ExpiresIn:   int64(expiresIn),
		Resource:    resource,
		TokenType:   "Bearer",
	}
	jsonResponse, err := json.Marshal(response)
	return jsonResponse, err
}

func makeResponseWithErrorData(err string, desc string) ([]byte, error) {
	responseBody := ErrorRespone{
		Err:  err,
		Desc: desc,
	}
	jsonResponse, e := json.Marshal(responseBody)
	return jsonResponse, e
}

type resourceTestData struct {
	source   Source
	endpoint string
	resource string
	miType   ID
}

type errorTestData struct {
	code          int
	err           string
	desc          string
	correlationid string
}

func Test_SystemAssigned_Returns_AcquireToken_Failure(t *testing.T) {
	testCases := []errorTestData{
		{code: http.StatusNotFound,
			err:           "",
			desc:          "",
			correlationid: "121212"},
		{code: http.StatusNotImplemented,
			err:           "",
			desc:          "",
			correlationid: "121212"},
		{code: http.StatusServiceUnavailable,
			err:           "",
			desc:          "",
			correlationid: "121212"},
		{code: http.StatusBadRequest,
			err:           "invalid_request",
			desc:          "Identity not found",
			correlationid: "121212",
		},
	}

	for _, testCase := range testCases {
		t.Run(http.StatusText(testCase.code), func(t *testing.T) {
			fakeErrorClient := mock.Client{}
			responseBody, err := makeResponseWithErrorData(testCase.err, testCase.desc)
			if err != nil {
				t.Fatalf("error while forming json response : %s", err.Error())
			}
			fakeErrorClient.AppendResponse(mock.WithHTTPStatusCode(testCase.code),
				mock.WithBody(responseBody))
			client, err := New(SystemAssigned(), WithHTTPClient(&fakeErrorClient))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.AcquireToken(context.Background(), resource)
			if err == nil {
				t.Fatalf("should have encountered the error")
			}
			var callErr errors.CallErr
			if errors.As(err, &callErr) {
				if !strings.Contains(err.Error(), testCase.err) {
					t.Fatalf("expected message '%s' in error, got %q", testCase.err, callErr.Error())
				}
				if callErr.Resp.StatusCode != testCase.code {
					t.Fatalf("expected status code %d, got %d", testCase.code, callErr.Resp.StatusCode)
				}
			} else {
				t.Fatalf("expected error of type %T, got %T", callErr, err)
			}
			if resp.AccessToken != "" {
				t.Fatalf("accesstoken should be empty")
			}
		})
	}
}

func Test_SystemAssigned_Returns_Token_Success(t *testing.T) {
	testCases := []resourceTestData{
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resource, miType: SystemAssigned()},
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resourceDefaultSuffix, miType: SystemAssigned()},
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resource, miType: UserAssignedClientID("clientId")},
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resourceDefaultSuffix, miType: UserAssignedResourceID("resourceId")},
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resourceDefaultSuffix, miType: UserAssignedObjectID("objectId")},
	}
	for _, testCase := range testCases {
		t.Run(string(testCase.source)+"-"+testCase.miType.value(), func(t *testing.T) {
			var localUrl *url.URL
			mockClient := mock.Client{}
			responseBody, err := getSuccessfulResponse(resource)
			if err != nil {
				t.Fatalf("error while forming json response : %s", err.Error())
			}
			mockClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusOK), mock.WithBody(responseBody), mock.WithCallback(func(r *http.Request) {
				localUrl = r.URL
			}))
			// resetting cache
			before := cacheManager
			defer func() { cacheManager = before }()
			cacheManager = storage.New(nil)
			client, err := New(testCase.miType, WithHTTPClient(&mockClient))
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.AcquireToken(context.Background(), testCase.resource)
			if err != nil {
				t.Fatal(err)
			}
			if localUrl == nil || !strings.HasPrefix(localUrl.String(), testCase.endpoint) {
				t.Fatalf("url request is not on %s got %s", testCase.endpoint, localUrl)
			}
			if testCase.miType.value() != systemAssignedManagedIdentity {
				if !strings.Contains(localUrl.String(), testCase.miType.value()) {
					t.Fatalf("url request does not contain the %s got %s", testCase.endpoint, testCase.miType.value())
				}
			}
			query := localUrl.Query()

			if query.Get(apiVersionQuerryParameterName) != imdsAPIVersion {
				t.Fatalf("api-version not on %s got %s", imdsAPIVersion, query.Get(apiVersionQuerryParameterName))
			}
			if query.Get(resourceQuerryParameterName) != strings.TrimSuffix(testCase.resource, "/.default") {
				t.Fatal("suffix /.default was not removed.")
			}
			switch i := testCase.miType.(type) {
			case UserAssignedClientID:
				if query.Get(miQueryParameterClientId) != i.value() {
					t.Fatalf("resource client-id is incorrect, wanted %s got %s", i.value(), query.Get(miQueryParameterClientId))
				}
			case UserAssignedResourceID:
				if query.Get(miQueryParameterResourceId) != i.value() {
					t.Fatalf("resource resource-id is incorrect, wanted %s got %s", i.value(), query.Get(miQueryParameterResourceId))
				}
			case UserAssignedObjectID:
				if query.Get(miQueryParameterObjectId) != i.value() {
					t.Fatalf("resource objectid is incorrect, wanted %s got %s", i.value(), query.Get(miQueryParameterObjectId))
				}
			}
			if result.Metadata.TokenSource != base.IdentityProvider {
				t.Fatalf("expected IndenityProvider tokensource, got %d", result.Metadata.TokenSource)
			}
			if result.AccessToken != token {
				t.Fatalf("wanted %q, got %q", token, result.AccessToken)
			}
			result, err = client.AcquireToken(context.Background(), testCase.resource)
			if err != nil {
				t.Fatal(err)
			}
			if result.Metadata.TokenSource != base.Cache {
				t.Fatalf("wanted cache token source, got %d", result.Metadata.TokenSource)
			}
			secondFakeClient, err := New(testCase.miType, WithHTTPClient(&mockClient))
			if err != nil {
				t.Fatal(err)
			}
			result, err = secondFakeClient.AcquireToken(context.Background(), testCase.resource)
			if err != nil {
				t.Fatal(err)
			}
			if result.Metadata.TokenSource != base.Cache {
				t.Fatalf("cache result wanted cache token source, got %d", result.Metadata.TokenSource)
			}
		})
	}
}

func TestCreatingIMDSClient(t *testing.T) {
	tests := []struct {
		name    string
		id      ID
		wantErr bool
	}{
		{
			name: "System Assigned",
			id:   SystemAssigned(),
		},
		{
			name: "Client ID",
			id:   UserAssignedClientID("test-client-id"),
		},
		{
			name: "Resource ID",
			id:   UserAssignedResourceID("test-resource-id"),
		},
		{
			name: "Object ID",
			id:   UserAssignedObjectID("test-object-id"),
		},
		{
			name:    "Empty Client ID",
			id:      UserAssignedClientID(""),
			wantErr: true,
		},
		{
			name:    "Empty Resource ID",
			id:      UserAssignedResourceID(""),
			wantErr: true,
		},
		{
			name:    "Empty Object ID",
			id:      UserAssignedObjectID(""),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := New(tt.id)
			if tt.wantErr {
				if err == nil {
					t.Fatal("client New() should return a error but did not.")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if client.miType.value() != tt.id.value() {
				t.Fatal("client New() did not assign a correct value to type.")
			}
		})
	}
}
