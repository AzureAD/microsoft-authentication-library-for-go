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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/storage"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

const (
	// Test Resources
	resource              = "https://management.azure.com"
	resourceDefaultSuffix = "https://management.azure.com/.default"
	token                 = "fake-access-token"
	fakeAzureArcFilePath  = "fake/fake"
	secretKey             = "secret.key"
	basicRealm            = "Basic realm="

	errorExpectedButGot      = "expected %v, got %v"
	errorFormingJsonResponse = "error while forming json response : %s"
)

type SuccessfulResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	Resource    string `json:"resource"`
	TokenType   string `json:"token_type"`
}

type ErrorResponse struct {
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
	responseBody := ErrorResponse{
		Err:  err,
		Desc: desc,
	}
	jsonResponse, e := json.Marshal(responseBody)
	return jsonResponse, e
}

func createMockFile(t *testing.T, path string, size int64) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	defer f.Close()

	if size > 0 {
		if err := f.Truncate(size); err != nil {
			t.Fatalf("failed to truncate file: %v", err)
		}
	}

	// Write the content to the file
	if _, err := f.WriteString("secret file data"); err != nil {
		t.Fatalf("failed to write to file: %v", err)
	}
	t.Cleanup(func() { os.Remove(path) })
}

func setEnvVars(t *testing.T, source Source) {
	switch source {
	case AzureArc:
		t.Setenv(identityEndpointEnvVar, "http://127.0.0.1:40342/metadata/identity/oauth2/token")
		t.Setenv(imdsEndVar, "http://169.254.169.254/metadata/identity/oauth2/token")
	case AppService:
		t.Setenv(identityEndpointEnvVar, "http://127.0.0.1:41564/msi/token")
		t.Setenv(identityHeaderEnvVar, "secret")
	case CloudShell:
		t.Setenv(msiEndpointEnvVar, "http://localhost:40342/metadata/identity/oauth2/token")
	case ServiceFabric:
		t.Setenv(identityEndpointEnvVar, "http://localhost:40342/metadata/identity/oauth2/token")
		t.Setenv(identityHeaderEnvVar, "secret")
		t.Setenv(identityServerThumbprintEnvVar, "thumbprint")
	}
}

func setCustomAzureArcPlatformPath(t *testing.T, path string) {
	originalFunc := getAzureArcPlatformPath
	getAzureArcPlatformPath = func(string) string {
		return path
	}

	t.Cleanup(func() { getAzureArcPlatformPath = originalFunc })
}

func setCustomAzureArcFilePath(t *testing.T, path string) {
	originalFunc := getAzureArcHimdsFilePath
	getAzureArcHimdsFilePath = func(string) string {
		return path
	}

	t.Cleanup(func() { getAzureArcHimdsFilePath = originalFunc })
}

func TestSource(t *testing.T) {
	for _, testCase := range []Source{AzureArc, DefaultToIMDS, CloudShell} {
		t.Run(string(testCase), func(t *testing.T) {
			setEnvVars(t, testCase)
			setCustomAzureArcFilePath(t, fakeAzureArcFilePath)

			actualSource, err := GetSource()
			if err != nil {
				t.Fatalf("error while getting source: %s", err.Error())
			}
			if actualSource != testCase {
				t.Fatalf(errorExpectedButGot, testCase, actualSource)
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
		source         Source
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
			source:         AzureArc,
		},
		{
			name: "Successful Request",
			mockResponses: []struct {
				body       string
				statusCode int
			}{
				{"Failed", http.StatusNotFound},
				{"Success", http.StatusOK},
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Success",
			maxRetries:     3,
			source:         DefaultToIMDS,
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
			source:         AzureArc,
		},
		{
			name: "Max Retries Reached",
			mockResponses: []struct {
				body       string
				statusCode int
			}{
				{"Error", http.StatusNotFound},
				{"Error", http.StatusInternalServerError},
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Error",
			maxRetries:     2,
			source:         DefaultToIMDS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mock.Client{}
			for _, resp := range tt.mockResponses {
				body := bytes.NewBufferString(resp.body)
				mockClient.AppendResponse(mock.WithBody(body.Bytes()), mock.WithHTTPStatusCode(resp.statusCode))
			}
			client, err := New(SystemAssigned(), WithHTTPClient(mockClient), WithRetryPolicyDisabled())
			if err != nil {
				t.Fatal(err)
			}
			reqBody := bytes.NewBufferString("Test Body")
			req, err := http.NewRequest("POST", "https://example.com", reqBody)
			if err != nil {
				t.Fatal(err)
			}
			finalResp, err := client.retry(tt.maxRetries, req)
			if err != nil {
				t.Fatal(err)
			}
			if finalResp.StatusCode != tt.expectedStatus {
				t.Fatalf("Expected status code %d, got %d", tt.expectedStatus, finalResp.StatusCode)
			}
			bodyBytes, err := io.ReadAll(finalResp.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}
			finalResp.Body.Close()
			if string(bodyBytes) != tt.expectedBody {
				t.Fatalf("Expected body %q, got %q", tt.expectedBody, bodyBytes)
			}
		})
	}
}

func Test_RetryPolicy_For_AcquireToken(t *testing.T) {
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
					t.Fatal(err)
				}
				if resp.AccessToken != token {
					t.Fatalf("wanted %q, got %q", token, resp.AccessToken)
				}
			}
			if testCase.disableRetry {
				if errorRetryCounter != 1 {
					t.Fatalf("expected Number of retry of 1, got %d", errorRetryCounter)
				}
			} else if errorRetryCounter != testCase.numberOfFails && testCase.numberOfFails < 3 {
				t.Fatalf("expected Number of retry of %d, got %d", testCase.numberOfFails, errorRetryCounter)
			}
		})
	}
}

func TestCacheScopes(t *testing.T) {
	before := cacheManager
	defer func() { cacheManager = before }()
	cacheManager = storage.New(nil)

	mc := mock.Client{}
	client, err := New(SystemAssigned(), WithHTTPClient(&mc))
	if err != nil {
		t.Fatal(err)
	}

	for _, r := range []string{"A", "B/.default"} {
		mc.AppendResponse(mock.WithBody(mock.GetAccessTokenBody(r, "", "", "", 3600)))
		for i := 0; i < 2; i++ {
			ar, err := client.AcquireToken(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			if ar.AccessToken != r {
				t.Fatalf("expected %q, got %q", r, ar.AccessToken)
			}
		}
	}
}

func TestAzureArcReturnsWhenHimdsFound(t *testing.T) {
	mockFilePath := filepath.Join(t.TempDir(), "himds")
	setCustomAzureArcFilePath(t, mockFilePath)

	// Create the mock himds file
	createMockFile(t, mockFilePath, 1024)

	actualSource, err := GetSource()
	if err != nil {
		t.Fatalf("error while getting source: %s", err.Error())
	}

	if actualSource != AzureArc {
		t.Fatalf(errorExpectedButGot, AzureArc, actualSource)
	}
}

func TestIMDSAcquireTokenReturnsTokenSuccess(t *testing.T) {
	testCases := []struct {
		resource string
		miType   ID
	}{
		{resource: resource, miType: SystemAssigned()},
		{resource: resourceDefaultSuffix, miType: SystemAssigned()},
		{resource: resource, miType: UserAssignedClientID("clientId")},
		{resource: resourceDefaultSuffix, miType: UserAssignedResourceID("resourceId")},
		{resource: resourceDefaultSuffix, miType: UserAssignedObjectID("objectId")},
	}
	for _, testCase := range testCases {
		t.Run(string(DefaultToIMDS)+"-"+testCase.miType.value(), func(t *testing.T) {
			endpoint := imdsDefaultEndpoint

			var localUrl *url.URL
			mockClient := mock.Client{}
			responseBody, err := getSuccessfulResponse(resource)
			if err != nil {
				t.Fatalf(errorFormingJsonResponse, err.Error())
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
			if localUrl == nil || !strings.HasPrefix(localUrl.String(), endpoint) {
				t.Fatalf("url request is not on %s got %s", endpoint, localUrl)
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

func TestCloudShellAcquireTokenReturnsTokenSuccess(t *testing.T) {
	testCases := []struct {
		resource string
		miType   ID
	}{
		{resource: resource, miType: SystemAssigned()},
		{resource: resourceDefaultSuffix, miType: SystemAssigned()},
		{resource: resource, miType: UserAssignedClientID("clientId")},
		{resource: resourceDefaultSuffix, miType: UserAssignedResourceID("resourceId")},
		{resource: resourceDefaultSuffix, miType: UserAssignedObjectID("objectId")},
	}
	for _, testCase := range testCases {
		t.Run(string(CloudShell)+"-"+testCase.miType.value(), func(t *testing.T) {
			endpoint := os.Getenv(msiEndpointEnvVar)

			var localUrl *url.URL
			mockClient := mock.Client{}
			responseBody, err := getSuccessfulResponse(resource)
			if err != nil {
				t.Fatalf(errorFormingJsonResponse, err.Error())
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
			if localUrl == nil || !strings.HasPrefix(localUrl.String(), endpoint) {
				t.Fatalf("url request is not on %s got %s", endpoint, localUrl)
			}
			query := localUrl.Query()

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
			if result.Metadata.TokenSource != base.IdentityProvider {
				t.Fatalf("expected IdentityProvider tokensource, got %d", result.Metadata.TokenSource)
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

func TestAzureArc(t *testing.T) {
	testCaseFilePath := filepath.Join(t.TempDir(), azureConnectedMachine)

	endpoint := azureArcEndpoint
	setEnvVars(t, AzureArc)
	setCustomAzureArcFilePath(t, fakeAzureArcFilePath)

	var localUrl *url.URL
	mockClient := mock.Client{}

	mockFilePath := filepath.Join(testCaseFilePath, secretKey)
	setCustomAzureArcPlatformPath(t, testCaseFilePath)

	createMockFile(t, mockFilePath, 0)

	headers := http.Header{}
	headers.Set(wwwAuthenticateHeaderName, basicRealm+filepath.Join(testCaseFilePath, secretKey))

	mockClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusUnauthorized),
		mock.WithHTTPHeader(headers),
		mock.WithCallback(func(r *http.Request) {
			localUrl = r.URL
		}))

	responseBody, err := getSuccessfulResponse(resource)
	if err != nil {
		t.Fatalf(errorFormingJsonResponse, err.Error())
	}
	mockClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusOK), mock.WithHTTPHeader(headers),
		mock.WithBody(responseBody), mock.WithCallback(func(r *http.Request) {
			localUrl = r.URL
		}))

	// resetting cache
	before := cacheManager
	defer func() { cacheManager = before }()
	cacheManager = storage.New(nil)

	client, err := New(SystemAssigned(), WithHTTPClient(&mockClient))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.AcquireToken(context.Background(), resourceDefaultSuffix)
	if err != nil {
		t.Fatal(err)
	}

	if localUrl == nil || !strings.HasPrefix(localUrl.String(), endpoint) {
		t.Fatalf("url request is not on %s got %s", endpoint, localUrl)
	}

	query := localUrl.Query()

	if query.Get(apiVersionQueryParameterName) != azureArcAPIVersion {
		t.Fatalf("api-version not on %s got %s", azureArcAPIVersion, query.Get(apiVersionQueryParameterName))
	}
	if query.Get(resourceQueryParameterName) != strings.TrimSuffix(resourceDefaultSuffix, "/.default") {
		t.Fatal("suffix /.default was not removed.")
	}
	if result.Metadata.TokenSource != base.IdentityProvider {
		t.Fatalf("expected IndenityProvider tokensource, got %d", result.Metadata.TokenSource)
	}
	if result.AccessToken != token {
		t.Fatalf("wanted %q, got %q", token, result.AccessToken)
	}
	result, err = client.AcquireToken(context.Background(), resource)
	if err != nil {
		t.Fatal(err)
	}
	if result.Metadata.TokenSource != base.Cache {
		t.Fatalf("wanted cache token source, got %d", result.Metadata.TokenSource)
	}
	secondFakeClient, err := New(SystemAssigned(), WithHTTPClient(&mockClient))
	if err != nil {
		t.Fatal(err)
	}
	result, err = secondFakeClient.AcquireToken(context.Background(), resource)
	if err != nil {
		t.Fatal(err)
	}
	if result.Metadata.TokenSource != base.Cache {
		t.Fatalf("cache result wanted cache token source, got %d", result.Metadata.TokenSource)
	}

}

func TestAzureArcOnlySystemAssignedSupported(t *testing.T) {
	setEnvVars(t, AzureArc)
	mockClient := mock.Client{}

	setCustomAzureArcFilePath(t, fakeAzureArcFilePath)
	for _, testCase := range []ID{
		UserAssignedClientID("client"),
		UserAssignedObjectID("ObjectId"),
		UserAssignedResourceID("resourceid")} {
		_, err := New(testCase, WithHTTPClient(&mockClient))
		fmt.Printf("%v", err)
		if err == nil {
			t.Fatal(`expected error: AzureArc not supported error"`)

		}
		if err.Error() != "AzureArc doesn't support user-assigned managed identities" {
			t.Fatalf(`expected error: AzureArc not supported error, got error: "%v"`, err)
		}

	}
}

func TestAzureArcPlatformSupported(t *testing.T) {
	setEnvVars(t, AzureArc)
	setCustomAzureArcFilePath(t, fakeAzureArcFilePath)
	before := cacheManager
	defer func() { cacheManager = before }()
	cacheManager = storage.New(nil)

	mockClient := mock.Client{}
	headers := http.Header{}
	headers.Set(wwwAuthenticateHeaderName, "Basic realm=/path/to/secret.key")

	mockClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusUnauthorized),
		mock.WithHTTPHeader(headers),
	)
	setCustomAzureArcPlatformPath(t, "")

	client, err := New(SystemAssigned(), WithHTTPClient(&mockClient))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.AcquireToken(context.Background(), resource)
	if err == nil || !strings.Contains(err.Error(), "platform not supported") {
		t.Fatalf(`expected error: "%v" got error: "%v"`, "platform not supported", err)

	}
	if result.AccessToken != "" {
		t.Fatalf("access token should be empty")
	}
}

func TestAzureArcErrors(t *testing.T) {
	setEnvVars(t, AzureArc)
	setCustomAzureArcFilePath(t, fakeAzureArcFilePath)
	testCaseFilePath := filepath.Join(t.TempDir(), "AzureConnectedMachineAgent")

	testCases := []struct {
		name          string
		headerValue   string
		expectedError string
		fileSize      int64
	}{
		{
			name:          "No www-authenticate header",
			expectedError: "response has no www-authenticate header",
		},
		{
			name:          "Basic realm= not found",
			headerValue:   "Basic ",
			expectedError: "basic realm= not found in the string, instead found: Basic ",
		},
		{
			name:          "Invalid file extension",
			headerValue:   "Basic realm=/path/to/secret.txt",
			expectedError: "invalid file extension, expected .key, got .txt",
		},
		{
			name:          "Invalid file path",
			headerValue:   "Basic realm=" + filepath.Join("path", "to", secretKey),
			expectedError: "invalid file path, expected " + testCaseFilePath + ", got " + filepath.Join("path", "to"),
		},
		{
			name:          "Unable to get file info",
			headerValue:   basicRealm + filepath.Join(testCaseFilePath, "2secret.key"),
			expectedError: "failed to get metadata",
		},
		{
			name:          "Invalid secret file size",
			headerValue:   basicRealm + filepath.Join(testCaseFilePath, secretKey),
			expectedError: "invalid secret file size, expected 4096, file size was 5000",
			fileSize:      5000,
		},
	}

	for _, testCase := range testCases {
		t.Run(string(testCase.name), func(t *testing.T) {
			before := cacheManager
			defer func() { cacheManager = before }()
			cacheManager = storage.New(nil)
			mockClient := mock.Client{}
			mockFilePath := filepath.Join(testCaseFilePath, secretKey)
			setCustomAzureArcPlatformPath(t, testCaseFilePath)
			createMockFile(t, mockFilePath, testCase.fileSize)
			headers := http.Header{}
			headers.Set(wwwAuthenticateHeaderName, testCase.headerValue)

			mockClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusUnauthorized),
				mock.WithHTTPHeader(headers),
			)

			responseBody, err := getSuccessfulResponse(resource)
			if err != nil {
				t.Fatalf(errorFormingJsonResponse, err.Error())
			}

			mockClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusOK), mock.WithHTTPHeader(headers),
				mock.WithBody(responseBody))

			client, err := New(SystemAssigned(), WithHTTPClient(&mockClient))
			if err != nil {
				t.Fatal(err)
				return
			}
			result, err := client.AcquireToken(context.Background(), resource)
			if err == nil || !strings.Contains(err.Error(), testCase.expectedError) {
				t.Fatalf(`expected error: "%v" got error: "%v"`, testCase.expectedError, err)

			}
			if result.AccessToken != "" {
				t.Fatal("access token should be empty")
			}
		})
	}
}

func TestCloudShellOnlySystemAssignedSupported(t *testing.T) {
	setEnvVars(t, CloudShell)
	mockClient := mock.Client{}

	for _, testCase := range []ID{
		UserAssignedClientID("client"),
		UserAssignedObjectID("ObjectId"),
		UserAssignedResourceID("resourceid")} {
		_, err := New(testCase, WithHTTPClient(&mockClient))
		fmt.Printf("%v", err)
		if err == nil {
			t.Fatal(`expected error: CloudShell not supported error"`)

		}
		if err.Error() != "CloudShell doesn't support user-assigned managed identities" {
			t.Fatalf(`expected error: AzureArc not supported error, got error: "%v"`, err)
		}

	}
}

func TestSystemAssignedReturnsAcquireTokenFailure(t *testing.T) {
	testCases := []struct {
		code int
		err  string
		desc string
	}{
		{code: http.StatusNotFound},
		{code: http.StatusNotImplemented},
		{code: http.StatusServiceUnavailable},
		{code: http.StatusBadRequest,
			err:  "invalid_request",
			desc: "Identity not found",
		},
	}

	for _, testCase := range testCases {
		t.Run(http.StatusText(testCase.code), func(t *testing.T) {
			setCustomAzureArcFilePath(t, fakeAzureArcFilePath)
			before := cacheManager
			defer func() { cacheManager = before }()
			cacheManager = storage.New(nil)
			fakeErrorClient := mock.Client{}
			responseBody, err := makeResponseWithErrorData(testCase.err, testCase.desc)
			if err != nil {
				t.Fatalf(errorFormingJsonResponse, err.Error())
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
			setCustomAzureArcFilePath(t, fakeAzureArcFilePath)
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
