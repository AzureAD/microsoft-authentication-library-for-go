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
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

const (
	// Test Resources
	resource              = "https://management.azure.com"
	resourceDefaultSuffix = "https://management.azure.com/.default"
	token                 = "fakeToken"
	azureArcTestEndpoint  = "http://localhost:40342/metadata/identity/oauth2/token"
)

type sourceTestData struct {
	source         Source
	endpoint       string
	expectedSource Source
	miType         ID
}

type resourceTestData struct {
	source     Source
	endpoint   string
	resource   string
	miType     ID
	apiVersion string
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

// Mock fileExists function for testing
var mockFileExists = func() bool {
	return true
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

func createMockFile(path string, size int64) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		panic(err)
	}

	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}

	if size > 0 {
		if err := f.Truncate(size); err != nil {
			panic(err)
		}
	}

	f.Close()
}

func createMockFileWithSize(path string, size int64) {
	createMockFile(path, size)
}

func setEnvVars(t *testing.T, source Source) {
	switch source {
	case AzureArc:
		t.Setenv(IdentityEndpointEnvVar, "http://localhost:40342/metadata/identity/oauth2/token")
		t.Setenv(ArcIMDSEnvVar, "http://localhost:40342 value")
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

func environmentVariablesHelper(source Source, endpoint string) {
	vars := map[string]string{
		"Source": string(source),
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
}

func Test_Get_Source(t *testing.T) {
	// todo update as required
	testCases := []sourceTestData{
		{source: AzureArc, endpoint: imdsEndpoint, expectedSource: AzureArc, miType: SystemAssigned()},
		{source: AzureArc, endpoint: imdsEndpoint, expectedSource: AzureArc, miType: UserAssignedClientID("clientId")},
		{source: AzureArc, endpoint: imdsEndpoint, expectedSource: AzureArc, miType: UserAssignedResourceID("resourceId")},
		{source: AzureArc, endpoint: imdsEndpoint, expectedSource: AzureArc, miType: UserAssignedObjectID("objectId")},
		{source: DefaultToIMDS, endpoint: imdsEndpoint, expectedSource: DefaultToIMDS, miType: SystemAssigned()},
		{source: DefaultToIMDS, endpoint: "", expectedSource: DefaultToIMDS, miType: SystemAssigned()},
	}

	for _, testCase := range testCases {
		t.Run(string(testCase.source), func(t *testing.T) {
			unsetEnvVars()
			setEnvVars(t, testCase.source)

			actualSource, err := GetSource(testCase.miType)
			if err != nil {
				t.Fatalf("error while getting source: %s", err.Error())
			}

			if actualSource != testCase.expectedSource {
				t.Errorf("expected %v, got %v", testCase.expectedSource, actualSource)
			}
		})
	}
}

func Test_SystemAssigned_Returns_Token_Success(t *testing.T) {
	testCases := []resourceTestData{
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resource, miType: SystemAssigned(), apiVersion: imdsAPIVersion},
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resourceDefaultSuffix, miType: SystemAssigned(), apiVersion: imdsAPIVersion},
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resource, miType: UserAssignedClientID("clientId"), apiVersion: imdsAPIVersion},
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resourceDefaultSuffix, miType: UserAssignedResourceID("resourceId"), apiVersion: imdsAPIVersion},
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resourceDefaultSuffix, miType: UserAssignedObjectID("objectId"), apiVersion: imdsAPIVersion},
		{source: AzureArc, endpoint: azureArcEndpoint, resource: resource, miType: SystemAssigned(), apiVersion: azureArcAPIVersion},
		{source: AzureArc, endpoint: azureArcEndpoint, resource: resourceDefaultSuffix, miType: SystemAssigned(), apiVersion: azureArcAPIVersion},
		{source: AzureArc, endpoint: azureArcEndpoint, resource: resource, miType: UserAssignedClientID("clientId"), apiVersion: azureArcAPIVersion},
		{source: AzureArc, endpoint: azureArcEndpoint, resource: resource, miType: UserAssignedObjectID("objectId"), apiVersion: azureArcAPIVersion},
		{source: AzureArc, endpoint: azureArcEndpoint, resource: resource, miType: UserAssignedResourceID("resourceId"), apiVersion: azureArcAPIVersion},
	}
	for _, testCase := range testCases {

		t.Run(string(testCase.source), func(t *testing.T) {
			unsetEnvVars()
			setEnvVars(t, testCase.source)

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
			if err != nil {
				if testCase.source == AzureArc && err.Error() == "Azure Arc doesn't support specifying a user-assigned managed identity at runtime" {
					return
				}
			}
			if !strings.HasPrefix(localUrl.String(), testCase.endpoint) {
				t.Fatalf("url request is not on %s got %s", testCase.endpoint, localUrl)
			}

			if !strings.Contains(localUrl.String(), testCase.miType.value()) {
				t.Fatalf("url request does not contain the %s got %s", testCase.endpoint, localUrl)
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

func Test_getAzureArcEnvironmentVariables(t *testing.T) {
	testCases := []struct {
		name           string
		envVars        map[string]string
		platform       string
		createMockFile bool
		expectedID     string
		expectedIMDS   string
	}{
		{
			name: "Both endpoints provided",
			envVars: map[string]string{
				IdentityEndpointEnvVar: "http://localhost:40342/metadata/identity/oauth2/token",
				ArcIMDSEnvVar:          "http://localhost:40342",
			},
			expectedID:   "http://localhost:40342/metadata/identity/oauth2/token",
			expectedIMDS: "http://localhost:40342",
		},
		{
			name: "Only identity endpoint provided, file doesn't exist",
			envVars: map[string]string{
				IdentityEndpointEnvVar: "http://localhost:40342/metadata/identity/oauth2/token",
			},
			createMockFile: false,
			platform:       "linux",

			expectedID: "http://localhost:40342/metadata/identity/oauth2/token",
		},
		{
			name: "Only arcImds endpoint provided, file doesn't exist",
			envVars: map[string]string{
				ArcIMDSEnvVar: "http://localhost:40342",
			},
			createMockFile: false,
			platform:       "linux",
			expectedIMDS:   "http://localhost:40342",
		},
		{
			name:           "Both endpoints missing, platform supported, file doesn't exist",
			platform:       "linux",
			createMockFile: false,
			expectedID:     "",
			expectedIMDS:   "",
		},
		{
			name: "Both endpoints, platform supported, file exists",
			envVars: map[string]string{
				IdentityEndpointEnvVar: "http://localhost:40342/metadata/identity/oauth2/token",
				ArcIMDSEnvVar:          "http://localhost:40342",
			},
			platform:       "linux",
			createMockFile: true,
			expectedID:     "",
			expectedIMDS:   "",
		},
		{
			name: "Only identity endpoint, platform supported, file exists",
			envVars: map[string]string{
				IdentityEndpointEnvVar: "http://localhost:40342/metadata/identity/oauth2/token",
				ArcIMDSEnvVar:          "",
			},
			platform:       "linux",
			createMockFile: true,
			expectedID:     "http://127.0.0.1:40342/metadata/identity/oauth2/token",
			expectedIMDS:   "N/A: himds executable exists",
		},
		{
			name: "Only arcIMds endpoint, platform supported, file exists",
			envVars: map[string]string{
				IdentityEndpointEnvVar: "",
				ArcIMDSEnvVar:          "http://localhost:40342",
			},
			platform:       "linux",
			createMockFile: true,
			expectedID:     "http://127.0.0.1:40342/metadata/identity/oauth2/token",
			expectedIMDS:   "N/A: himds executable exists",
		},
		{
			name:           "Endpoints missing, no file exists",
			platform:       "linux",
			createMockFile: false,
			expectedID:     "",
			expectedIMDS:   "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.envVars {
				t.Setenv(k, v)
			}

			os.Setenv("GOOS", tc.platform)
			if tc.createMockFile {
				if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
					mockFilePath := azureArcFileDetection[tc.platform]
					createMockFile(mockFilePath, 0)
					defer os.Remove(mockFilePath)
				} else {
					t.Skip("Skipping part of the test because current platform is not linux or windows")
				}
			}

			id, imds := getAzureArcEnvironmentVariables()

			if id != tc.expectedID {
				t.Fatalf("expected ID %v, got %v", tc.expectedID, id)
			}
			if imds != tc.expectedIMDS {
				t.Fatalf("expected IMDS %v, got %v", tc.expectedIMDS, imds)
			}
		})
	}
}

func Test_validateAzureArcEnvironment(t *testing.T) {
	testCases := []struct {
		name             string
		identityEndpoint string
		imdsEndpoint     string
		platform         string
		fileExistsResult bool
		expectedResult   bool
	}{
		{
			name:             "Both endpoints provided",
			identityEndpoint: "endpoint",
			imdsEndpoint:     "endpoint",
			platform:         "linux",
			expectedResult:   true,
		},
		{
			name:             "Only identityEndpoint provided",
			identityEndpoint: "endpoint",
			imdsEndpoint:     "",
			platform:         "linux",
			fileExistsResult: false,
			expectedResult:   false,
		},
		{
			name:             "Only imdsEndpoint provided",
			identityEndpoint: "",
			imdsEndpoint:     "endpoint",
			platform:         "linux",
			fileExistsResult: false,
			expectedResult:   false,
		},
		{
			name:             "No endpoints provided",
			identityEndpoint: "",
			imdsEndpoint:     "",
			platform:         "linux",
			fileExistsResult: false,
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
			platform:         "linux",
			fileExistsResult: false,
			expectedResult:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockFileExists = func() bool {
				return tc.fileExistsResult
			}

			result := validateAzureArcEnvironment(tc.identityEndpoint, tc.imdsEndpoint, tc.platform)
			if result != tc.expectedResult {
				t.Fatalf("expected %v, got %v", tc.expectedResult, result)
			}
		})
	}
}

// Test function
func Test_fileExists(t *testing.T) {
	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "test_file")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	print(fileExists(tmpFile.Name()))

	// Test case: file exists
	if !fileExists(tmpFile.Name()) {
		t.Errorf("expected file to exist, but it doesn't")
	}

	// Test case: file does not exist
	nonExistentFilePath := tmpFile.Name() + "_nonexistent"
	if fileExists(nonExistentFilePath) {
		t.Errorf("expected file not to exist, but it does")
	}
}

func Test_handleAzureArcResponse(t *testing.T) {
	testCases := []struct {
		name           string
		statusCode     int
		headers        map[string]string
		expectedError  string
		platform       string
		prepareMockEnv func(*testing.T)
		cleanupMockEnv func()
	}{
		{
			name:          "Not 401 error",
			statusCode:    http.StatusOK,
			headers:       map[string]string{},
			expectedError: "managed identity error: 200",
			platform:      "windows",
		},
		{
			name:          "No www-authenticate header",
			statusCode:    http.StatusUnauthorized,
			headers:       map[string]string{},
			expectedError: "response has no www-authenticate header",
			platform:      "windows",
		},
		{
			name:          "Basic realm= not found",
			statusCode:    http.StatusUnauthorized,
			headers:       map[string]string{wwwAuthenticateHeaderName: "Basic "},
			expectedError: "basic realm= not found in the string",
			platform:      "windows",
		},
		{
			name:          "Platform not supported",
			statusCode:    http.StatusUnauthorized,
			headers:       map[string]string{wwwAuthenticateHeaderName: "Basic realm=/path/to/secret.key"},
			expectedError: "platform not supported",
			platform:      "android",
		},
		{
			name:          "Invalid file extension",
			statusCode:    http.StatusUnauthorized,
			headers:       map[string]string{wwwAuthenticateHeaderName: "Basic realm=/path/to/secret.txt"},
			expectedError: "invalid file extension",
			platform:      "windows",
			prepareMockEnv: func(t *testing.T) {
				if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
					t.Skip("Skipping test because current platform is not linux or windows")
				}
				createMockFile("/path/to/secret.key", 0)
				supportedAzureArcPlatforms["windows"] = "/path/to/"
			},
			cleanupMockEnv: func() {
				os.Remove("/path/to/secret.key")
			},
		},
		{
			name:          "Invalid file path",
			statusCode:    http.StatusUnauthorized,
			headers:       map[string]string{wwwAuthenticateHeaderName: "Basic realm=/path/to/secret.key"},
			expectedError: "invalid file path",
			platform:      "windows",
			prepareMockEnv: func(t *testing.T) {
				if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
					t.Skip("Skipping test because current platform is not linux or windows")
				}
				createMockFile("/path/to/secret.key", 0)
				supportedAzureArcPlatforms["windows"] = "/path/to/"
			},
			cleanupMockEnv: func() {
				os.Remove("/path/to/secret.key")
			},
		},
		{
			name:          "Unable to get file info",
			statusCode:    http.StatusUnauthorized,
			headers:       map[string]string{wwwAuthenticateHeaderName: "Basic realm=/path/to/secret.key"},
			expectedError: "unable to get file info",
			platform:      "windows",
			prepareMockEnv: func(t *testing.T) {
				if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
					t.Skip("Skipping test because current platform is not linux or windows")
				}
				createMockFile("/path/to/secret.key", 0)
				supportedAzureArcPlatforms["windows"] = "/path/to/"
			},
			cleanupMockEnv: func() {
				os.Remove("/path/to/secret.key")
			},
		},
		{
			name:          "Invalid secret file size",
			statusCode:    http.StatusUnauthorized,
			headers:       map[string]string{wwwAuthenticateHeaderName: "Basic realm=/path/to/large_secret.key"},
			expectedError: "invalid secret file size",
			platform:      "windows",
			prepareMockEnv: func(t *testing.T) {
				if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
					t.Skip("Skipping test because current platform is not linux or windows")
				}
				createMockFile("/path/to/secret.key", 0)
				supportedAzureArcPlatforms["windows"] = "/path/to/"
			},
			cleanupMockEnv: func() {
				os.Remove("/path/to/secret.key")
			},
		},
		{
			name:          "Unable to read the secret file",
			statusCode:    http.StatusUnauthorized,
			headers:       map[string]string{wwwAuthenticateHeaderName: "Basic realm=/unreadable/path/to/secret.key"},
			expectedError: "unable to read the secret file",
			platform:      "windows",
			prepareMockEnv: func(t *testing.T) {
				if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
					t.Skip("Skipping test because current platform is not linux or windows")
				}
				createMockFile("/path/to/secret.key", 0)
				supportedAzureArcPlatforms["windows"] = "/path/to/"
			},
			cleanupMockEnv: func() {
				os.Remove("/path/to/secret.key")
			},
		},
		{
			name:          "token request fail",
			statusCode:    http.StatusUnauthorized,
			headers:       map[string]string{wwwAuthenticateHeaderName: "Basic realm=/unreadable/path/to/secret.key"},
			expectedError: "error creating http request",
			platform:      "windows",
			prepareMockEnv: func(t *testing.T) {
				if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
					t.Skip("Skipping test because current platform is not linux or windows")
				}
				createMockFile("/path/to/secret.key", 0)
				supportedAzureArcPlatforms["windows"] = "/path/to/"
			},
			cleanupMockEnv: func() {
				os.Remove("/path/to/secret.key")
			},
		},
	}

	skipPlatformSpecificTests := map[string]bool{
		"Invalid file extension":         true,
		"Invalid file path":              true,
		"Unable to get file info":        true,
		"Invalid secret file size":       true,
		"Unable to read the secret file": true,
		"token request fail":             true,
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if skipPlatformSpecificTests[tc.name] && tc.platform != "linux" && tc.platform != "windows" {
				t.Skip("Skipping test because current platform is not linux or windows")
			}

			// Apply any modifications to the map if needed
			if tc.prepareMockEnv != nil {
				tc.prepareMockEnv(t)
			}

			unsetEnvVars()
			setEnvVars(t, AzureArc)

			// Create a mock response
			response := &http.Response{
				StatusCode: tc.statusCode,
				Header:     make(http.Header),
			}

			for k, v := range tc.headers {
				response.Header.Set(k, v)
			}

			client := &Client{}
			_, err := client.handleAzureArcResponse(response, context.Background(), "", tc.platform)

			if tc.cleanupMockEnv != nil {
				tc.cleanupMockEnv()

			}

			if err == nil || err.Error() != tc.expectedError {
				t.Fatalf("expected error %v, got %v", tc.expectedError, err)
			}
		})
	}
}
