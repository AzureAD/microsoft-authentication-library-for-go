// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package managedidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

const (
	// Test Resources
	resource              = "https://demo.azure.com"
	resourceDefaultSuffix = "https://demo.azure.com/.default"
	token                 = "fakeToken"
)

type mockEnvironmentVariables struct {
	vars map[string]string
}

type sourceTestData struct {
	source         Source
	endpoint       string
	expectedSource Source
	miType         ID
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
	correlationID string
}

type SuccessfulResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresOn   int64  `json:"expires_on"`
	Resource    string `json:"resource"`
	TokenType   string `json:"token_type"`
}

type ErrorResponse struct {
	Err  string `json:"error"`
	Desc string `json:"error_description"`
}

func getSuccessfulResponse(resource string) ([]byte, error) {
	expiresOn := time.Now().Add(1 * time.Hour).Unix()
	response := SuccessfulResponse{
		AccessToken: token,
		ExpiresOn:   expiresOn,
		Resource:    resource,
		TokenType:   "Bearer",
	}
	jsonResponse, err := json.Marshal(response)
	return jsonResponse, err
}

func makeResponseWithErrorData(err string, desc string) ([]byte, error) {
	responseBody := ErrorResponse{
		Err:  err,
		Desc: desc,
	}
	jsonResponse, e := json.Marshal(responseBody)
	return jsonResponse, e
}

func setEnvVars(t *testing.T, source Source) {
	switch source {
	case AzureArc:
		t.Setenv(IdentityEndpointEnvVar, "identityEndpointEnvVar value")
		t.Setenv(ArcIMDSEnvVar, "arcIMDSEnvVar value")
	case AppService:
		t.Setenv(IdentityEndpointEnvVar, "identityEndpointEnvVar value")
		t.Setenv(IdentityHeaderEnvVar, "identityHeaderEnvVar value")
	case CloudShell:
		t.Setenv(MsiEndpointEnvVar, "msiEndpointEnvVar value")
	case ServiceFabric:
		t.Setenv(IdentityEndpointEnvVar, "identityEndpointEnvVar value")
		t.Setenv(IdentityHeaderEnvVar, "identityHeaderEnvVar value")
		t.Setenv(IdentityServerThumbprintEnvVar, "identityServerThumbprintEnvVar value")
	}
}

func unsetEnvVars() {
	os.Unsetenv(IdentityEndpointEnvVar)
	os.Unsetenv(IdentityHeaderEnvVar)
	os.Unsetenv(IdentityServerThumbprintEnvVar)
	os.Unsetenv(ArcIMDSEnvVar)
	os.Unsetenv(MsiEndpointEnvVar)
}

func environmentVariablesHelper(source Source, endpoint string) *mockEnvironmentVariables {
	vars := map[string]string{
		"Source": source.String(),
	}

	switch source {
	case AppService:
		vars[IdentityEndpointEnvVar] = endpoint
		vars[IdentityHeaderEnvVar] = "secret"
	case DefaultToIMDS:
		vars[ArcIMDSEnvVar] = endpoint
	case ServiceFabric:
		vars[IdentityEndpointEnvVar] = endpoint
		vars[IdentityHeaderEnvVar] = "secret"
		vars[IdentityServerThumbprintEnvVar] = "thumbprint"
	case CloudShell:
		vars[MsiEndpointEnvVar] = endpoint
	case AzureArc:
		vars[IdentityEndpointEnvVar] = endpoint
		vars[ArcIMDSEnvVar] = endpoint
	}

	return &mockEnvironmentVariables{vars: vars}
}

func Test_Get_Source(t *testing.T) {
	// todo update as required
	testCases := []sourceTestData{
		{source: AzureArc, endpoint: azureArcEndpoint, expectedSource: AzureArc, miType: SystemAssigned()},
		{source: AzureArc, endpoint: azureArcEndpoint, expectedSource: AzureArc, miType: UserAssignedClientID("clientId")},
		{source: AzureArc, endpoint: azureArcEndpoint, expectedSource: AzureArc, miType: UserAssignedResourceID("resourceId")},
		{source: AzureArc, endpoint: azureArcEndpoint, expectedSource: AzureArc, miType: UserAssignedObjectID("objectId")},
		{source: DefaultToIMDS, endpoint: imdsEndpoint, expectedSource: DefaultToIMDS, miType: SystemAssigned()},
		{source: DefaultToIMDS, endpoint: "", expectedSource: DefaultToIMDS, miType: SystemAssigned()},
	}

	for _, testCase := range testCases {
		t.Run(testCase.source.String(), func(t *testing.T) {
			unsetEnvVars()
			setEnvVars(t, testCase.source)

			actualSource, err := GetSource(testCase.miType)

			if err != nil {
				if fmt.Sprintf("%s %s", testCase.source, getSourceError) == err.Error() {
					return
				} else {
					t.Fatalf("expected error but got nil")
				}
			} else {
				if actualSource != testCase.expectedSource {
					t.Errorf("expected %v, got %v", testCase.expectedSource, actualSource)
				}
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
		// {source: AzureArc, endpoint: azureArcEndpoint, resource: resourceDefaultSuffix, miType: SystemAssigned()},
		// {source: AzureArc, endpoint: azureArcEndpoint, resource: resourceDefaultSuffix, miType: SystemAssigned()},
	}
	for _, testCase := range testCases {

		t.Run(string(testCase.source), func(t *testing.T) {
			var localUrl *url.URL
			mockClient := mock.Client{}
			responseBody, err := getSuccessfulResponse(resource)
			if err != nil {
				t.Fatalf("error while forming json response : %s", err.Error())
			}
			mockClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusOK), mock.WithBody(responseBody), mock.WithCallback(func(r *http.Request) {
				localUrl = r.URL
			}))
			client, err := New(testCase.miType, WithHTTPClient(&mockClient))

			if err != nil {
				t.Fatal(err)
			}
			result, err := client.AcquireToken(context.Background(), testCase.resource)
			if !strings.HasPrefix(localUrl.String(), testCase.endpoint) {
				t.Fatalf("url request is not on %s got %s", testCase.endpoint, localUrl)
			}
			if !strings.Contains(localUrl.String(), testCase.miType.value()) {
				t.Fatalf("url request does not contain the %s got %s", testCase.endpoint, localUrl)
			}
			query := localUrl.Query()

			if query.Get(apiVersionQueryParameterName) != imdsAPIVersion {
				t.Fatalf("api-version not on %s got %s", imdsAPIVersion, query.Get(apiVersionQueryParameterName))
			}
			if query.Get(resourceQueryParameterName) != strings.TrimSuffix(testCase.resource, "/.default") {
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
			if err != nil {
				t.Fatal(err)
			}
			if result.AccessToken != token {
				t.Fatalf("wanted %q, got %q", token, result.AccessToken)
			}

		})
	}
}

func Test_SystemAssigned_Returns_AcquireToken_Failure(t *testing.T) {
	testCases := []errorTestData{
		{code: http.StatusNotFound,
			err:           "",
			desc:          "",
			correlationID: "121212"},
		{code: http.StatusNotImplemented,
			err:           "",
			desc:          "",
			correlationID: "121212"},
		{code: http.StatusServiceUnavailable,
			err:           "",
			desc:          "",
			correlationID: "121212"},
		{code: http.StatusBadRequest,
			err:           "invalid_request",
			desc:          "Identity not found",
			correlationID: "121212",
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
				t.Fatalf("access token should be empty")
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
