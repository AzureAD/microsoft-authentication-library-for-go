// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package managedidentity

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

const (
	// test Resources
	resource              = "https://demo.azure.com"
	resourceDefaultSuffix = "https://demo.azure.com/.default"

	token = "fakeToken"
)

type SuccessfulResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresOn   int64  `json:"expires_on"`
	Resource    string `json:"resource"`
	TokenType   string `json:"token_type"`
	ClientID    string `json:"client_id"`
}

type ErrorRespone struct {
	Err  string `json:"error"`
	Desc string `json:"error_description"`
}

type response struct {
	body     []byte
	callback func(*http.Request)
	code     int
}

func getSuccessfulResponse(resource string) []byte {
	expiresOn := time.Now().Add(1 * time.Hour).Unix()
	response := SuccessfulResponse{
		AccessToken: token,
		ExpiresOn:   expiresOn,
		Resource:    resource,
		TokenType:   "Bearer",
		ClientID:    "client_id",
	}
	jsonResponse, _ := json.Marshal(response)
	return jsonResponse
}

func makeResponseWithErrorData(err string, desc string) []byte {
	responseBody := ErrorRespone{
		Err:  err,
		Desc: desc,
	}
	if len(err) == 0 && len(desc) == 0 {
		jsonResponse, _ := json.Marshal(responseBody)
		return jsonResponse
	}
	jsonResponse, _ := json.Marshal(responseBody)
	return jsonResponse
}

type resourceTestData struct {
	source   Source
	endpoint string
	resource string
}

type errorTestData struct {
	code          int
	err           string
	desc          string
	correlationid string
}

func createResourceData() []resourceTestData {
	return []resourceTestData{
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resource},
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resourceDefaultSuffix},
	}
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
		t.Run(strconv.Itoa(testCase.code), func(t *testing.T) {
			fakeErrorClient := mock.Client{}
			fakeErrorClient.AppendCustomResponse(testCase.code, mock.WithBody(makeResponseWithErrorData(testCase.err, testCase.desc)))
			client, err := New(SystemAssigned(), WithHTTPClient(&fakeErrorClient))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.AcquireToken(context.Background(), resource)
			if err == nil {
				t.Fatalf("testManagedIdentity: Should have encountered the error")
			}
			var callErr errors.CallErr
			if errors.As(err, &callErr) {
				callErr = err.(errors.CallErr)
				if !strings.Contains(err.Error(), testCase.err) {
					t.Fatalf("testManagedIdentity: expected message '%s' in error, got %q", testCase.err, callErr.Error())
				}
				if callErr.Resp.StatusCode != testCase.code {
					t.Fatalf("testManagedIdentity: expected status code %d, got %d", testCase.code, callErr.Resp.StatusCode)
				}
			} else {
				t.Fatalf("testManagedIdentity: expected error of type %T, got %T", callErr.Error(), err)
			}
			if resp.AccessToken != "" {
				t.Fatalf("testManagedIdentity: accesstoken should be nil")
			}
		})
	}
}

func Test_SystemAssigned_Returns_Token_Success(t *testing.T) {
	testCases := createResourceData()
	for _, testCase := range testCases {

		t.Run(string(testCase.source), func(t *testing.T) {
			var url string
			mockClient := mock.Client{}
			mockClient.AppendCustomResponse(http.StatusOK, mock.WithBody(getSuccessfulResponse(resource)), mock.WithCallback(func(r *http.Request) { url = r.URL.String() }))
			client, err := New(SystemAssigned(), WithHTTPClient(&mockClient))

			if err != nil {
				t.Fatal(err)
			}
			result, err := client.AcquireToken(context.Background(), testCase.resource)
			if !strings.HasPrefix(url, testCase.endpoint) {
				t.Fatalf("TestManagedIdentity: URL request is not on %s fgot %s", testCase.endpoint, url)
			}
			if err != nil {
				t.Fatalf("TestManagedIdentity: unexpected nil error from TestManagedIdentity %s", err.Error())
			}
			if result.AccessToken != token {
				t.Fatalf("TestManagedIdentity: wanted %q, got %q", token, result.AccessToken)
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
			id:   ClientID("test-client-id"),
		},
		{
			name: "Resource ID",
			id:   ResourceID("test-resource-id"),
		},
		{
			name: "Object ID",
			id:   ObjectID("test-object-id"),
		},
		{
			name:    "Empty Client ID",
			id:      ClientID(""),
			wantErr: true,
		},
		{
			name:    "Empty Resource ID",
			id:      ResourceID(""),
			wantErr: true,
		},
		{
			name:    "Empty Object ID",
			id:      ObjectID(""),
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
				t.Fatal("client New() error while creating client")
			} else {
				if client.miType.value() != tt.id.value() {
					t.Fatal("client New() did not assign a correct value to type.")
				}
			}
		})
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
		},
		{
			name:     "System Assigned",
			id:       SystemAssigned(),
			resource: "https://management.azure.com/.default",
		},
		{
			name:     "Client ID",
			id:       ClientID("test-client-id"),
			resource: "https://storage.azure.com",
		},
		{
			name:     "Resource ID",
			id:       ResourceID("test-resource-id"),
			resource: "https://vault.azure.net",
		},
		{
			name:     "Object ID",
			id:       ObjectID("test-object-id"),
			resource: "https://graph.microsoft.com",
		},
		{
			name:     "With Claims",
			id:       SystemAssigned(),
			resource: "https://management.azure.com",
			claims:   "test-claims",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := createIMDSAuthRequest(context.Background(), tt.id, tt.resource, tt.claims)
			if tt.wantErr {
				if err == nil {
					t.Fatal(err)
				}
				return
			}
			if req == nil {
				t.Fatal("createIMDSAuthRequest() returned nil request")
				return
			}
			if req.Method != http.MethodGet {
				t.Fatal("createIMDSAuthRequest() method is not GET")
			}
			if !strings.HasPrefix(req.URL.String(), imdsEndpoint) {
				t.Fatal("createIMDSAuthRequest() URL is not matched.")
			}
			query := req.URL.Query()

			if query.Get(apiVersionQuerryParameterName) != "2018-02-01" {
				t.Fatal("createIMDSAuthRequest() api-version missmatch")
			}
			if query.Get(resourceQuerryParameterName) != strings.TrimSuffix(tt.resource, "/.default") {
				t.Fatal("createIMDSAuthRequest() resource does not ahve suffix removed ")
			}
			switch i := tt.id.(type) {
			case ClientID:
				if query.Get(miQuerryParameterClientId) != i.value() {
					t.Fatal("createIMDSAuthRequest() resource client-id is incorrect")
				}
			case ResourceID:
				if query.Get(miQuerryParameterResourceId) != i.value() {
					t.Fatal("createIMDSAuthRequest() resource resource-id is incorrect")
				}
			case ObjectID:
				if query.Get(miQuerryParameterObjectId) != i.value() {
					t.Fatal("createIMDSAuthRequest() resource objectiid is incorrect")
				}
			case systemAssignedValue: // not adding anything
			default:
				t.Fatal("createIMDSAuthRequest() unsupported type")

			}

		})
	}
}
