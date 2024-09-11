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
		Body:       io.NopCloser(strings.NewReader(makeResponseWithErrorData(e.errResponse))),
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

func getMsiErrorResponse() string {
	response := ErrorResponse{
		StatusCode:    500,
		Message:       "An unexpected error occurred while fetching the AAD Token.",
		CorrelationID: "7d0c9763-ff1d-4842-a3f3-6d49e64f4513",
	}
	jsonResponse, _ := json.Marshal(response)
	return string(jsonResponse)
}

func getMsiErrorResponseNotFound() string {
	response := ErrorResponse{
		StatusCode:    500,
		Message:       "An unexpected error occurred while fetching the AAD Token.",
		CorrelationID: "7d0c9763-ff1d-4842-a3f3-6d49e64f4513",
	}
	jsonResponse, _ := json.Marshal(response)
	return string(jsonResponse)
}

func getMsiErrorResponseNoRetry() string {
	response := ErrorResponse{
		StatusCode:    123,
		Message:       "Not one of the retryable error responses",
		CorrelationID: "7d0c9763-ff1d-4842-a3f3-6d49e64f4513",
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
		{StatusCode: 404, Message: "IMDS service not available", CorrelationID: "121212"},
		{StatusCode: 501, Message: "Service error 1", CorrelationID: "121212"},
		{StatusCode: 503, Message: "Service error 2", CorrelationID: "121212"},
		{StatusCode: 400, Message: "invalid id", CorrelationID: "121212"},
	}

	for _, testCase := range testCases {
		t.Run(strconv.Itoa(testCase.StatusCode), func(t *testing.T) {
			fakeErrorClient := errorClient{errResponse: testCase}
			client, err := fakeMIClient(SystemAssigned(), WithHTTPClient(&fakeErrorClient))

			if err != nil {
				t.Fatal(err)
			}

			resp, err := client.AcquireToken(context.Background(), resource)

			if resp.AccessToken != "" {
				t.Fatalf("testManagedIdentity: accesstoken should be nil")
			}
			if err == nil {
				t.Fatalf("testManagedIdentity: Should have encountered the error")
			}
			if err.Error() != fmt.Errorf("failed to authenticate with status code %d ", testCase.StatusCode).Error() {
				t.Fatalf(`unexpected error "%s"`, err)

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
		t.Log("0------")
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

			switch tt.id.(type) {
			case ClientID:
				if query.Get(miQuerryParameterClientId) != tt.id.value() {
					t.Fatal("createIMDSAuthRequest() client_id does not match with the id value")
				}
			case ResourceID:
				if query.Get(miQuerryParameterResourceId) != tt.id.value() {
					t.Fatal("createIMDSAuthRequest() resource id does not match with the id value")
				}
			case ObjectID:
				if query.Get(miQuerryParameterObjectId) != tt.id.value() {
					t.Fatal("createIMDSAuthRequest() object id does not match with the id value")
				}
			}
		})
	}
}
