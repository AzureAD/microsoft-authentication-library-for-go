// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package managedidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
)

const (
	// test Resources
	resource              = "https://demo.azure.com"
	resourceDefaultSuffix = "https://demo.azure.com/.default"
)

type HttpRequest struct {
	Source   Source
	Resource string
	Identity ID
}

type SuccessfulResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresOn   int64  `json:"expires_on"`
	Resource    string `json:"resource"`
	TokenType   string `json:"token_type"`
	ClientID    string `json:"client_id"`
}

type ErrorResponse struct {
	StatusCode    int    `json:"statusCode"`
	Message       string `json:"message"`
	CorrelationID string `json:"correlationId,omitempty"`
}

type fakeClient struct{}
type errorClient struct {
	errResponse ErrorResponse
}

func fakeMIClient(mangedIdentityId ID, options ...ClientOption) (Client, error) {
	fakeClient, err := New(mangedIdentityId, options...)

	if err != nil {
		return Client{}, err
	}

	return fakeClient, nil
}

func (*fakeClient) CloseIdleConnections()  {}
func (*errorClient) CloseIdleConnections() {}

func (*fakeClient) Do(req *http.Request) (*http.Response, error) {
	w := http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(getSuccessfulResponse(resource))),
		Header:     make(http.Header),
	}
	return &w, nil
}

func (e *errorClient) Do(req *http.Request) (*http.Response, error) {
	w := http.Response{
		StatusCode: e.errResponse.StatusCode,
		Body:       io.NopCloser(strings.NewReader(e.errResponse.Message)),
		Header:     make(http.Header),
	}
	return &w, nil
}

func getSuccessfulResponse(resource string) string {
	expiresOn := time.Now().Add(1 * time.Hour).Unix()
	response := SuccessfulResponse{
		AccessToken: "fakeToken",
		ExpiresOn:   expiresOn,
		Resource:    resource,
		TokenType:   "Bearer",
		ClientID:    "client_id",
	}
	jsonResponse, _ := json.Marshal(response)
	return string(jsonResponse)
}

func makeResponseWithErrorData(errRsp ErrorResponse) string {
	response := ErrorResponse{
		StatusCode:    errRsp.StatusCode,
		Message:       errRsp.Message,
		CorrelationID: errRsp.CorrelationID,
	}
	jsonResponse, _ := json.Marshal(response)
	return string(jsonResponse)
}

func computeUri(endpoint string, queryParameters map[string][]string) string {
	if len(queryParameters) == 0 {
		return endpoint
	}

	queryString := url.Values{}
	for key, values := range queryParameters {
		for _, value := range values {
			queryString.Add(key, value)
		}
	}

	return endpoint + "?" + queryString.Encode()
}

func expectedRequest(source Source, resource string, id ID) (*http.Request, error) {
	return expectedRequestWithId(source, resource, id)
}

func expectedRequestWithId(_ Source, resource string, id ID) (*http.Request, error) {
	var endpoint string
	headers := http.Header{}
	queryParameters := make(map[string][]string)

	//check with source when added different sources.
	endpoint = imdsEndpoint
	queryParameters["api-version"] = []string{"2018-02-01"}
	queryParameters["resource"] = []string{resource}
	headers.Add("Metadata", "true")

	switch id.(type) {
	case ClientID:
		queryParameters[miQuerryParameterClientId] = []string{id.value()}
	case ResourceID:
		queryParameters[miQuerryParameterResourceId] = []string{id.value()}
	case ObjectID:
		queryParameters[miQuerryParameterObjectId] = []string{id.value()}
	case systemAssignedValue:
		// not adding anything
	default:
		return nil, fmt.Errorf("Type not supported")
	}

	uri, err := url.Parse(computeUri(endpoint, queryParameters))
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: "GET",
		URL:    uri,
		Header: headers,
	}

	return req, nil
}

func ExpectedResponse(statusCode int, response string) http.Response {
	return http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(response)),
	}
}

type resourceTestData struct {
	source   Source
	endpoint string
	resource string
}

func createResourceData() []resourceTestData {
	return []resourceTestData{
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resource},
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resourceDefaultSuffix},
	}
}

func Test_SystemAssigned_Returns_Token_Failure(t *testing.T) {
	testCases := []ErrorResponse{
		{StatusCode: http.StatusNotFound, Message: ``, CorrelationID: "121212"},
		{StatusCode: http.StatusNotImplemented, Message: ``, CorrelationID: "121212"},
		{StatusCode: http.StatusServiceUnavailable, Message: ``, CorrelationID: "121212"},
		{StatusCode: http.StatusBadRequest,
			Message:       `{"error": "invalid_request", "error_description": "Identity not found"}`,
			CorrelationID: "121212",
		},
	}

	for _, testCase := range testCases {
		t.Run(strconv.Itoa(testCase.StatusCode), func(t *testing.T) {
			fakeErrorClient := errorClient{errResponse: testCase}
			client, err := fakeMIClient(SystemAssigned(), WithHTTPClient(&fakeErrorClient))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.AcquireToken(context.Background(), resource)
			if err == nil {
				t.Fatalf("testManagedIdentity: Should have encountered the error")
			}
			switch e := err.(type) {
			case errors.CallErr:
				if actual := err.Error(); !strings.Contains(e.Error(), testCase.Message) {
					t.Fatalf("testManagedIdentity: expected response body in error, got %q", actual)
				}
				if e.Resp.StatusCode != testCase.StatusCode {
					t.Fatal("testManagedIdentity: got unexpected status code.")
				}
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

		t.Run(testCase.source.String(), func(t *testing.T) {
			fakeHTTPClient := fakeClient{}
			client, err := fakeMIClient(SystemAssigned(), WithHTTPClient(&fakeHTTPClient))

			if err != nil {
				t.Fatal(err)
			}

			result, err := client.AcquireToken(context.Background(), testCase.resource)

			if err != nil {
				t.Errorf("TestManagedIdentity: unexpected nil error from TestManagedIdentity")
			}
			var tokenScope = []string{"the_scope"}
			expected := accesstokens.TokenResponse{
				AccessToken:   "fakeToken",
				ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
				ExtExpiresOn:  internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
				GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
				TokenType:     "TokenType",
			}
			if result.AccessToken != expected.AccessToken {
				t.Fatalf(`unexpected access token "%s"`, result.AccessToken)
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
