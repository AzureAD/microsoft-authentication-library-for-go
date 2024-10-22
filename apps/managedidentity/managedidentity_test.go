// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package managedidentity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
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
	wrongSecretKey        = "2secret.key"
	basicRealm            = "Basic realm="
	thisShouldFail        = "This should fail"

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
	defer f.Close() // Ensure the file is closed

	if size > 0 {
		if err := f.Truncate(size); err != nil {
			t.Fatalf("failed to truncate file: %v", err)
		}
	}
}

func getMockFilePath(t *testing.T) (string, error) {
	tempDir := t.TempDir()
	mockFilePath := filepath.Join(tempDir, "AzureConnectedMachineAgent")
	return mockFilePath, nil
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

func unsetEnvVars(t *testing.T) {
	t.Setenv(identityEndpointEnvVar, "")
	t.Setenv(identityHeaderEnvVar, "")
	t.Setenv(identityServerThumbprintEnvVar, "")
	t.Setenv(imdsEndVar, "")
	t.Setenv(msiEndpointEnvVar, "")
}

func setCustomAzureArcPlatformPath(t *testing.T, path string) {
	originalFunc := getAzureArcPlatformPath
	getAzureArcPlatformPath = func(string) string {
		return path
	}

	t.Cleanup(func() { getAzureArcPlatformPath = originalFunc })
}

func setCustomAzureArcFilePath(t *testing.T, path string) {
	originalFunc := getAzureArcFilePath
	getAzureArcFilePath = func(string) string {
		return path
	}

	t.Cleanup(func() { getAzureArcFilePath = originalFunc })
}

func TestGetSource(t *testing.T) {
	// todo update as required
	testCases := []struct {
		name           string
		source         Source
		endpoint       string
		expectedSource Source
		miType         ID
	}{
		{name: "testAzureArcSystemAssigned", source: AzureArc, endpoint: imdsDefaultEndpoint, expectedSource: AzureArc, miType: SystemAssigned()},
		{name: "testAzureArcUserClientAssigned", source: AzureArc, endpoint: imdsDefaultEndpoint, expectedSource: AzureArc, miType: UserAssignedClientID("clientId")},
		{name: "testAzureArcUserResourceAssigned", source: AzureArc, endpoint: imdsDefaultEndpoint, expectedSource: AzureArc, miType: UserAssignedResourceID("resourceId")},
		{name: "testAzureArcUserObjectAssigned", source: AzureArc, endpoint: imdsDefaultEndpoint, expectedSource: AzureArc, miType: UserAssignedObjectID("objectId")},
		{name: "testDefaultToImds", source: DefaultToIMDS, endpoint: imdsDefaultEndpoint, expectedSource: DefaultToIMDS, miType: SystemAssigned()},
		{name: "testDefaultToImdsClientAssigned", source: DefaultToIMDS, endpoint: imdsDefaultEndpoint, expectedSource: DefaultToIMDS, miType: UserAssignedClientID("clientId")},
		{name: "testDefaultToImdsResourceAssigned", source: DefaultToIMDS, endpoint: imdsDefaultEndpoint, expectedSource: DefaultToIMDS, miType: UserAssignedResourceID("resourceId")},
		{name: "testDefaultToImdsObjectAssigned", source: DefaultToIMDS, endpoint: imdsDefaultEndpoint, expectedSource: DefaultToIMDS, miType: UserAssignedObjectID("objectId")},
		{name: "testDefaultToImdsEmptyEndpoint", source: DefaultToIMDS, endpoint: "", expectedSource: DefaultToIMDS, miType: SystemAssigned()},
		{name: "testDefaultToImdsLinux", source: DefaultToIMDS, endpoint: imdsDefaultEndpoint, expectedSource: DefaultToIMDS, miType: SystemAssigned()},
		{name: "testDefaultToImdsEmptyEndpointLinux", source: DefaultToIMDS, endpoint: "", expectedSource: DefaultToIMDS, miType: SystemAssigned()},
	}

	for _, testCase := range testCases {
		t.Run(string(testCase.source), func(t *testing.T) {
			unsetEnvVars(t)
			setEnvVars(t, testCase.source)
			setCustomAzureArcFilePath(t, fakeAzureArcFilePath)

			actualSource, err := GetSource(testCase.miType)
			if err != nil {
				t.Fatalf("error while getting source: %s", err.Error())
			}

			if actualSource != testCase.expectedSource {
				t.Errorf(errorExpectedButGot, testCase.expectedSource, actualSource)
			}
		})
	}
}

func TestAzureArcReturnsWhenHimdsFound(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Skipping test on macOS as HIMDS is not supported")
	}

	testCases := []struct {
		name           string
		source         Source
		endpoint       string
		expectedSource Source
		miType         ID
	}{
		{name: "testAzureArcSystemAssigned", source: AzureArc, endpoint: "imdsDefaultEndpoint", expectedSource: AzureArc, miType: SystemAssigned()},
	}

	for _, testCase := range testCases {
		t.Run(string(testCase.source), func(t *testing.T) {
			unsetEnvVars(t)

			actualSource, err := GetSource(testCase.miType)
			if err != nil {
				t.Fatalf("error while getting source: %s", err.Error())
			}

			if actualSource != testCase.expectedSource {
				t.Errorf(errorExpectedButGot, testCase.expectedSource, actualSource)
			}
		})
	}
}

func TestIMDSAcquireTokenReturnsTokenSuccess(t *testing.T) {
	testCases := []struct {
		source     Source
		endpoint   string
		resource   string
		miType     ID
		apiVersion string
	}{
		{source: DefaultToIMDS, endpoint: imdsDefaultEndpoint, resource: resource, miType: SystemAssigned(), apiVersion: imdsAPIVersion},
		{source: DefaultToIMDS, endpoint: imdsDefaultEndpoint, resource: resourceDefaultSuffix, miType: SystemAssigned(), apiVersion: imdsAPIVersion},
		{source: DefaultToIMDS, endpoint: imdsDefaultEndpoint, resource: resource, miType: UserAssignedClientID("clientId"), apiVersion: imdsAPIVersion},
		{source: DefaultToIMDS, endpoint: imdsDefaultEndpoint, resource: resourceDefaultSuffix, miType: UserAssignedResourceID("resourceId"), apiVersion: imdsAPIVersion},
		{source: DefaultToIMDS, endpoint: imdsDefaultEndpoint, resource: resourceDefaultSuffix, miType: UserAssignedObjectID("objectId"), apiVersion: imdsAPIVersion},
	}
	for _, testCase := range testCases {
		t.Run(string(testCase.source)+"-"+testCase.miType.value(), func(t *testing.T) {
			unsetEnvVars(t)
			setEnvVars(t, testCase.source)
			setCustomAzureArcFilePath(t, fakeAzureArcFilePath)

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
			if localUrl == nil || !strings.HasPrefix(localUrl.String(), testCase.endpoint) {
				t.Fatalf("url request is not on %s got %s", testCase.endpoint, localUrl)
			}
			if testCase.miType.value() != systemAssignedManagedIdentity {
				if !strings.Contains(localUrl.String(), testCase.miType.value()) {
					t.Fatalf("url request does not contain the %s got %s", testCase.endpoint, testCase.miType.value())
				}
			}

			query := localUrl.Query()

			if query.Get(apiVersionQueryParameterName) != testCase.apiVersion {
				t.Fatalf("api-version not on %s got %s", testCase.apiVersion, query.Get(apiVersionQueryParameterName))
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

func TestAzureArcAcquireTokenReturnsTokenSuccess(t *testing.T) {
	testCaseFilePath, err := getMockFilePath(t)
	if err != nil {
		t.Fatalf("failed to get mock file path: %v", err)
	}

	testCases := []struct {
		source            Source
		endpoint          string
		resource          string
		miType            ID
		apiVersion        string
		failFirstResponse bool
	}{
		{source: AzureArc, endpoint: azureArcEndpoint, resource: resource, miType: SystemAssigned(), apiVersion: azureArcAPIVersion, failFirstResponse: false},
		{source: AzureArc, endpoint: azureArcEndpoint, resource: resourceDefaultSuffix, miType: SystemAssigned(), apiVersion: azureArcAPIVersion, failFirstResponse: false},
		{source: AzureArc, endpoint: azureArcEndpoint, resource: resource, miType: SystemAssigned(), apiVersion: azureArcAPIVersion, failFirstResponse: true},
	}

	for _, testCase := range testCases {
		t.Run(string(testCase.source)+"-"+testCase.miType.value(), func(t *testing.T) {
			unsetEnvVars(t)
			setEnvVars(t, testCase.source)
			setCustomAzureArcFilePath(t, fakeAzureArcFilePath)

			var localUrl *url.URL
			mockClient := mock.Client{}

			if err != nil {
				t.Fatalf(errorFormingJsonResponse, err.Error())
			}

			if testCase.failFirstResponse {
				mockFilePath := filepath.Join(testCaseFilePath, secretKey)
				setCustomAzureArcPlatformPath(t, testCaseFilePath)
				createMockFile(t, mockFilePath, 0)

				defer os.Remove(mockFilePath)

				headers := http.Header{}
				headers.Add(wwwAuthenticateHeaderName, basicRealm+filepath.Join(testCaseFilePath, secretKey))

				mockClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusUnauthorized),
					mock.WithHTTPHeader(headers),
					mock.WithCallback(func(r *http.Request) { localUrl = r.URL }))
			}

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
			if localUrl == nil || !strings.HasPrefix(localUrl.String(), testCase.endpoint) {
				t.Fatalf("url request is not on %s got %s", testCase.endpoint, localUrl)
			}
			if testCase.miType.value() != systemAssignedManagedIdentity {
				if !strings.Contains(localUrl.String(), testCase.miType.value()) {
					t.Fatalf("url request does not contain the %s got %s", testCase.endpoint, testCase.miType.value())
				}
			}

			query := localUrl.Query()

			if query.Get(apiVersionQueryParameterName) != testCase.apiVersion {
				t.Fatalf("api-version not on %s got %s", testCase.apiVersion, query.Get(apiVersionQueryParameterName))
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

func TestSystemAssignedReturnsAcquireTokenFailure(t *testing.T) {
	testCases := []struct {
		code          int
		err           string
		desc          string
		correlationID string
	}{
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
			unsetEnvVars(t)
			setCustomAzureArcFilePath(t, fakeAzureArcFilePath)

			fakeErrorClient := mock.Client{}
			responseBody, err := makeResponseWithErrorData(testCase.err, testCase.desc)
			if err != nil {
				t.Fatalf(errorFormingJsonResponse, err.Error())
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
			unsetEnvVars(t)
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

func TestAzureArcUserAssignedFailure(t *testing.T) {
	tests := []struct {
		name    string
		id      ID
		wantErr bool
	}{
		{
			wantErr: true,
			name:    "Client ID",
			id:      UserAssignedClientID("test-client-id"),
		},
		{
			wantErr: true,
			name:    "Resource ID",
			id:      UserAssignedResourceID("test-resource-id"),
		},
		{
			wantErr: true,
			name:    "Object ID",
			id:      UserAssignedObjectID("test-object-id"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unsetEnvVars(t)
			setEnvVars(t, AzureArc)
			client, err := New(tt.id)
			if tt.wantErr {
				if err == nil {
					t.Fatal("client New() should return a error but did not.")
				}

				if err.Error() != "azure Arc doesn't support user assigned managed identities" {
					t.Fatalf("expected error message 'azure Arc doesn't support user assigned managed identities', got %s", err.Error())
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

func TestValidateAzureArcEnvironment(t *testing.T) {
	testCases := []struct {
		name             string
		identityEndpoint string
		imdsEndpoint     string
		platform         string
		expectedResult   bool
	}{
		{
			name:             "Both endpoints provided",
			identityEndpoint: "endpoint",
			imdsEndpoint:     "endpoint",
			platform:         runtime.GOOS,
			expectedResult:   true,
		},
		{
			name:             "Only identityEndpoint provided",
			identityEndpoint: "endpoint",
			imdsEndpoint:     "",
			platform:         runtime.GOOS,
			expectedResult:   false,
		},
		{
			name:             "Only imdsEndpoint provided",
			identityEndpoint: "",
			imdsEndpoint:     "endpoint",
			platform:         runtime.GOOS,
			expectedResult:   false,
		},
		{
			name:             "No endpoints provided",
			identityEndpoint: "",
			imdsEndpoint:     "",
			platform:         runtime.GOOS,
			expectedResult:   false,
		},
		{
			name:             "Platform not supported",
			identityEndpoint: "",
			imdsEndpoint:     "",
			platform:         "darwin",
			expectedResult:   false,
		},
		{
			name:             "File does not exist",
			identityEndpoint: "",
			imdsEndpoint:     "",
			platform:         runtime.GOOS,
			expectedResult:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setCustomAzureArcFilePath(t, fakeAzureArcFilePath)

			result := isAzureArcEnvironment(tc.identityEndpoint, tc.imdsEndpoint, tc.platform)
			if result != tc.expectedResult {
				t.Fatalf(errorExpectedButGot, tc.expectedResult, result)
			}
		})
	}
}

func TestHandleAzureArcResponse(t *testing.T) {
	testCaseFilePath, err := getMockFilePath(t)
	if err != nil {
		t.Fatalf("failed to get mock file path: %v", err)
	}

	testCases := []struct {
		name           string
		statusCode     int
		headers        map[string]string
		expectedError  string
		platform       string
		createMockFile bool
		context        context.Context
		prepareMockEnv func(*testing.T)
		cleanupMockEnv func()
	}{
		{
			name:          "Not 401 error",
			statusCode:    http.StatusOK,
			headers:       map[string]string{},
			expectedError: "managed identity error: 200",
			platform:      runtime.GOOS,
		},
		{
			name:          "No www-authenticate header",
			statusCode:    http.StatusUnauthorized,
			headers:       map[string]string{},
			expectedError: "response has no www-authenticate header",
			platform:      runtime.GOOS,
		},
		{
			name:          "Basic realm= not found",
			statusCode:    http.StatusUnauthorized,
			headers:       map[string]string{wwwAuthenticateHeaderName: "Basic "},
			expectedError: "basic realm= not found in the string, instead found: Basic ",
			platform:      runtime.GOOS,
		},
		{
			name:          "Platform not supported",
			statusCode:    http.StatusUnauthorized,
			headers:       map[string]string{wwwAuthenticateHeaderName: "Basic realm=/path/to/secret.key"},
			expectedError: "platform not supported, expected linux or windows, got testPlatform",
			platform:      "testPlatform",
			context:       context.Background(),
		},
		{
			name:           "Invalid file extension",
			statusCode:     http.StatusUnauthorized,
			headers:        map[string]string{wwwAuthenticateHeaderName: "Basic realm=/path/to/secret.txt"},
			expectedError:  "invalid file extension, expected .key, got .txt",
			platform:       runtime.GOOS,
			createMockFile: true,
		},
		{
			name:           "Invalid file path",
			statusCode:     http.StatusUnauthorized,
			headers:        map[string]string{wwwAuthenticateHeaderName: "Basic realm=/path/to/secret.key"},
			expectedError:  "invalid file path, expected " + filepath.Dir(testCaseFilePath) + " got /path/to/secret.key",
			platform:       runtime.GOOS,
			createMockFile: true,
		},
		{
			name:       "Unable to get file info",
			statusCode: http.StatusUnauthorized,
			headers:    map[string]string{wwwAuthenticateHeaderName: basicRealm + filepath.Join(testCaseFilePath, wrongSecretKey)},
			expectedError: func() string {
				if runtime.GOOS == "windows" {
					return "failed to get metadata for " + filepath.Join(testCaseFilePath, wrongSecretKey) + " due to error: CreateFile " + filepath.Join(testCaseFilePath, wrongSecretKey) + ": The system cannot find the file specified."
				}
				return "failed to get metadata for " + filepath.Join(testCaseFilePath, wrongSecretKey) + " due to error: stat " + filepath.Join(testCaseFilePath, wrongSecretKey) + ": no such file or directory"
			}(),
			platform:       runtime.GOOS,
			createMockFile: true,
		},
		{
			name:           "Invalid secret file size",
			statusCode:     http.StatusUnauthorized,
			headers:        map[string]string{wwwAuthenticateHeaderName: basicRealm + filepath.Join(testCaseFilePath, secretKey)},
			expectedError:  "invalid secret file size, expected 4096, file size was 5000",
			platform:       runtime.GOOS,
			createMockFile: true,
		},
		{
			name:           "token request fail",
			statusCode:     http.StatusUnauthorized,
			headers:        map[string]string{wwwAuthenticateHeaderName: basicRealm + filepath.Join(testCaseFilePath, secretKey)},
			expectedError:  "error creating http request net/http: nil Context",
			platform:       runtime.GOOS,
			createMockFile: true,
			context:        context.Background(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.platform+" "+tc.name, func(t *testing.T) {
			if tc.platform != "linux" && tc.platform != "windows" && tc.platform != "testPlatform" {
				t.Skip("Skipping test because current platform is not linux or windows")
			}

			unsetEnvVars(t)
			setEnvVars(t, AzureArc)

			response := &http.Response{
				StatusCode: tc.statusCode,
				Header:     make(http.Header),
			}

			for k, v := range tc.headers {
				response.Header.Set(k, v)
			}

			if tc.createMockFile {
				mockFilePath := filepath.Join(testCaseFilePath, secretKey)
				setCustomAzureArcPlatformPath(t, testCaseFilePath)

				if tc.name == "Invalid secret file size" {
					createMockFile(t, mockFilePath, 5000)
				} else {
					createMockFile(t, mockFilePath, 0)
				}

				defer os.Remove(mockFilePath)
			}

			client := &Client{}

			if tc.name == "token request fail" {
				tc.context = nil
			}

			_, err := client.handleAzureArcResponse(tc.context, response, "", tc.platform)

			if err == nil || err.Error() != tc.expectedError {
				t.Fatalf("expected error: \"%v\"\ngot error: \"%v\"", tc.expectedError, err)
			}
		})
	}
}
