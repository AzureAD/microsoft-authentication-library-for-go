// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package managedidentity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
			client, err := New(SystemAssigned(), WithHTTPClient(&fakeErrorClient), WithRetryPolicyDisabled())
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

func TestRetryFunction(t *testing.T) {
	tests := []struct {
		name          string
		mockResponses []struct {
			body       string
			statusCode int
		}
		expectedStatus int
		expectedBody   string
		maxRetries     int
		requestBody    string
	}{
		{
			name: "Successful Request",
			mockResponses: []struct {
				body       string
				statusCode int
			}{
				{"Failed", http.StatusInternalServerError},
				{"Success", http.StatusOK},
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Success",
			maxRetries:     3,
			requestBody:    "Test Body",
		},
		{
			name: "Max Retries Reached",
			mockResponses: []struct {
				body       string
				statusCode int
			}{
				{"Error", http.StatusInternalServerError},
				{"Error", http.StatusInternalServerError},
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Error",
			maxRetries:     2,
			requestBody:    "Test Body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mock.Client{}
			for _, resp := range tt.mockResponses {
				body := bytes.NewBufferString(resp.body)
				mockClient.AppendResponse(mock.WithBody(body.Bytes()), mock.WithHTTPStatusCode(resp.statusCode))
			}
			reqBody := bytes.NewBufferString(tt.requestBody)
			req, _ := http.NewRequest("POST", "https://example.com", reqBody)
			finalResp, err := retry(tt.maxRetries, mockClient, req)
			if err != nil {
				t.Fatalf("error was not expected %s", err)
			}
			if finalResp.StatusCode != tt.expectedStatus {
				t.Fatalf("Expected status code %d, got %d", tt.expectedStatus, finalResp.StatusCode)
			}
			bodyBytes, err := io.ReadAll(finalResp.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}
			finalResp.Body.Close() // Close the body after reading
			if string(bodyBytes) != tt.expectedBody {
				t.Fatalf("Expected body %q, got %q", tt.expectedBody, bodyBytes)
			}
			if req.Body != nil {
				reqBodyBytes, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("Failed to read request body: %v", err)
				}
				req.Body.Close()

				if string(reqBodyBytes) != tt.requestBody {
					t.Fatalf("Expected request body %q, got %q", tt.requestBody, reqBodyBytes)
				}
			}
		})
	}
}

func Test_RetryPolicy_For_AcquireToken_Failure(t *testing.T) {
	testCases := []struct {
		numberOfFails int
		expectedFail  bool
		disableRetry  bool
	}{
		{numberOfFails: 1, expectedFail: false, disableRetry: false},
		{numberOfFails: 1, expectedFail: true, disableRetry: true},
		{numberOfFails: 1, expectedFail: true, disableRetry: true},
		{numberOfFails: 2, expectedFail: false, disableRetry: false},
		{numberOfFails: 3, expectedFail: true, disableRetry: false},
	}
	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("Testing retry policy with %d ", testCase.numberOfFails), func(t *testing.T) {
			fakeErrorClient := mock.Client{}
			responseBody, err := makeResponseWithErrorData("sample error", "sample error desc")
			if err != nil {
				t.Fatalf("error while forming json response : %s", err.Error())
			}
			errorRetryCounter := 0
			for i := 0; i < testCase.numberOfFails; i++ {
				fakeErrorClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusInternalServerError),
					mock.WithBody(responseBody), mock.WithCallback(func(r *http.Request) {
						errorRetryCounter++
					}))
			}
			if !testCase.expectedFail {
				successRespBody, err := getSuccessfulResponse(resource)
				if err != nil {
					t.Fatalf("error while forming json response : %s", err.Error())
				}
				fakeErrorClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusAccepted),
					mock.WithBody(successRespBody))
			}
			var client Client
			if testCase.disableRetry {
				client, err = New(SystemAssigned(), WithHTTPClient(&fakeErrorClient), WithRetryPolicyDisabled())
			} else {
				client, err = New(SystemAssigned(), WithHTTPClient(&fakeErrorClient))

			}
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.AcquireToken(context.Background(), resource, WithClaims("noCache"))
			if testCase.expectedFail {
				if err == nil {
					t.Fatalf("should have encountered the error")
				}
				if resp.AccessToken != "" {
					t.Fatalf("accesstoken should be empty")
				}
			} else {
				if err != nil {
					t.Fatalf("should have encountered the error")
				}
				if resp.AccessToken != token {
					t.Fatalf("wanted %q, got %q", token, resp.AccessToken)
				}
			}
			if testCase.disableRetry {
				if errorRetryCounter != 1 {
					t.Fatalf("expected Number of retry of 1, got %d", errorRetryCounter)
				}
			} else {
				if errorRetryCounter != testCase.numberOfFails && testCase.numberOfFails < 3 {
					t.Fatalf("expected Number of retry of %d, got %d", testCase.numberOfFails, errorRetryCounter)
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
