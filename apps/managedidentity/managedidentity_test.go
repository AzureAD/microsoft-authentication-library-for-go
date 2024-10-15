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
	name           string
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

func createMockFile(t *testing.T, path string, size int64) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	if size > 0 {
		if err := f.Truncate(size); err != nil {
			t.Fatalf("failed to truncate file: %v", err)
		}
	}
	f.Close()
}

func getMockFilePath(t *testing.T) (string, error) {
	tempDir := t.TempDir()
	mockFilePath := filepath.Join(tempDir, "AzureConnectedMachineAgent")

	return mockFilePath, nil
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

func Test_Get_Source(t *testing.T) {
	// todo update as required
	testCases := []sourceTestData{
		{name: "testAzureArcSystemAssigned", source: AzureArc, endpoint: imdsEndpoint, expectedSource: AzureArc, miType: SystemAssigned()},
		{name: "testAzureArcUserClientAssigned", source: AzureArc, endpoint: imdsEndpoint, expectedSource: AzureArc, miType: UserAssignedClientID("clientId")},
		{name: "testAzureArcUserResourceAssigned", source: AzureArc, endpoint: imdsEndpoint, expectedSource: AzureArc, miType: UserAssignedResourceID("resourceId")},
		{name: "testAzureArcUserObjectAssigned", source: AzureArc, endpoint: imdsEndpoint, expectedSource: AzureArc, miType: UserAssignedObjectID("objectId")},
		{name: "testDefaultToImds", source: DefaultToIMDS, endpoint: imdsEndpoint, expectedSource: DefaultToIMDS, miType: SystemAssigned()},
		{name: "testDefaultToImdsClientAssigned", source: DefaultToIMDS, endpoint: imdsEndpoint, expectedSource: DefaultToIMDS, miType: UserAssignedClientID("clientId")},
		{name: "testDefaultToImdsResourceAssigned", source: DefaultToIMDS, endpoint: imdsEndpoint, expectedSource: DefaultToIMDS, miType: UserAssignedResourceID("resourceId")},
		{name: "testDefaultToImdsObjectAssigned", source: DefaultToIMDS, endpoint: imdsEndpoint, expectedSource: DefaultToIMDS, miType: UserAssignedObjectID("objectId")},
		{name: "testDefaultToImdsEmptyEndpoint", source: DefaultToIMDS, endpoint: "", expectedSource: DefaultToIMDS, miType: SystemAssigned()},
		{name: "testDefaultToImdsLinux", source: DefaultToIMDS, endpoint: imdsEndpoint, expectedSource: DefaultToIMDS, miType: SystemAssigned()},
		{name: "testDefaultToImdsEmptyEndpointLinux", source: DefaultToIMDS, endpoint: "", expectedSource: DefaultToIMDS, miType: SystemAssigned()},
	}

	for _, testCase := range testCases {
		t.Run(string(testCase.source), func(t *testing.T) {
			unsetEnvVars()
			setEnvVars(t, testCase.source)

			if runtime.GOOS == "linux" {
				originalPath := azureArcOsToFileMap[runtime.GOOS]
				azureArcOsToFileMap[runtime.GOOS] = "fake/fake"

				if testCase.name == "testDefaultToImdsLinux" || testCase.name == "testDefaultToImdsEmptyEndpointLinux" {
					azureArcOsToFileMap[runtime.GOOS] = originalPath
				}
			}

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

func Test_AcquireToken_Returns_Token_Success(t *testing.T) {
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

			if runtime.GOOS == "linux" {
				azureArcOsToFileMap[runtime.GOOS] = "fake/fake"
			}

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
				if testCase.source == AzureArc && err.Error() == "Azure Arc doesn't support user assigned managed identities" {
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

func Test_getAndValidateAzureArcEnvVars(t *testing.T) {
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
			createMockFile: false,
			expectedID:     "http://localhost:40342/metadata/identity/oauth2/token",
			expectedIMDS:   "http://localhost:40342",
		},
		{
			name: "Only identity endpoint provided",
			envVars: map[string]string{
				IdentityEndpointEnvVar: "http://localhost:40342/metadata/identity/oauth2/token",
			},
			platform:       runtime.GOOS,
			createMockFile: false,
			expectedID:     "http://localhost:40342/metadata/identity/oauth2/token",
		},
		{
			name: "Only arcImds endpoint provided",
			envVars: map[string]string{
				ArcIMDSEnvVar: "http://localhost:40342",
			},
			platform:       runtime.GOOS,
			createMockFile: false,
			expectedIMDS:   "http://localhost:40342",
		},
		// Windows Specific Tests
		{
			name: "Only identity endpoint provided, file exists",
			envVars: map[string]string{
				IdentityEndpointEnvVar: "http://localhost:40342/metadata/identity/oauth2/token",
				ArcIMDSEnvVar:          "",
			},
			platform:       "windows",
			createMockFile: true,
			expectedID:     "http://127.0.0.1:40342/metadata/identity/oauth2/token",
			expectedIMDS:   "N/A: himds executable exists",
		},
		{
			name: "Only arcIMds endpoint, file exists",
			envVars: map[string]string{
				IdentityEndpointEnvVar: "",
				ArcIMDSEnvVar:          "http://localhost:40342",
			},
			platform:       "windows",
			createMockFile: true,
			expectedID:     "http://127.0.0.1:40342/metadata/identity/oauth2/token",
			expectedIMDS:   "N/A: himds executable exists",
		},
		// Linux Specific Tests
		{
			name: "Only identity endpoint provided, linux platform supported, file exists",
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
			name: "Only arcIMds endpoint, linux platform supported, file exists",
			envVars: map[string]string{
				IdentityEndpointEnvVar: "",
				ArcIMDSEnvVar:          "http://localhost:40342",
			},
			platform:       "linux",
			createMockFile: true,
			expectedID:     "http://127.0.0.1:40342/metadata/identity/oauth2/token",
			expectedIMDS:   "N/A: himds executable exists",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.platform+" "+tc.name, func(t *testing.T) {
			unsetEnvVars()

			if tc.platform != "" && runtime.GOOS != tc.platform {
				t.Skip("Skipping test because current platform is not " + tc.platform)
			}

			for k, v := range tc.envVars {
				t.Setenv(k, v)
			}

			if tc.createMockFile {
				homeDir, err := os.UserHomeDir()
				if err != nil {
					t.Fatalf("failed to get user home directory: %v", err)
				}
				mockFilePath := filepath.Join(homeDir, "AzureConnectedMachineAgent", "himds.exe")
				if runtime.GOOS == "linux" {
					mockFilePath = filepath.Join(homeDir, "AzureConnectedMachineAgent", "himds")
				}

				azureArcOsToFileMap[tc.platform] = mockFilePath
				createMockFile(t, mockFilePath, 0)
				defer os.Remove(mockFilePath)
			} else {
				azureArcOsToFileMap[tc.platform] = "fake"
			}

			id, imds, _ := getAndValidateAzureArcEnvVars()

			if id != tc.expectedID {
				t.Fatalf("expected ID %v, got %v", tc.expectedID, id)
			}
			if imds != tc.expectedIMDS {
				t.Fatalf("expected IMDS %v, got %v", tc.expectedIMDS, imds)
			}
		})
	}
}

func Test_fileExists(t *testing.T) {
	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "test_file")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

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
			expectedError: "basic realm= not found in the string",
			platform:      runtime.GOOS,
		},
		{
			name:          "Platform not supported",
			statusCode:    http.StatusUnauthorized,
			headers:       map[string]string{wwwAuthenticateHeaderName: "Basic realm=/path/to/secret.key"},
			expectedError: "platform not supported",
			platform:      "testPlatform",
		},
		{
			name:           "Invalid file extension",
			statusCode:     http.StatusUnauthorized,
			headers:        map[string]string{wwwAuthenticateHeaderName: "Basic realm=/path/to/secret.txt"},
			expectedError:  "invalid file extension",
			platform:       runtime.GOOS,
			createMockFile: true,
		},
		{
			name:           "Invalid file path",
			statusCode:     http.StatusUnauthorized,
			headers:        map[string]string{wwwAuthenticateHeaderName: "Basic realm=/path/to/secret.key"},
			expectedError:  "invalid file path",
			platform:       runtime.GOOS,
			createMockFile: true,
		},
		{
			name:           "Unable to get file info",
			statusCode:     http.StatusUnauthorized,
			headers:        map[string]string{wwwAuthenticateHeaderName: "Basic realm=" + filepath.Join(testCaseFilePath, "2secret.key")},
			expectedError:  "unable to get file info",
			platform:       runtime.GOOS,
			createMockFile: true,
		},
		{
			name:           "Invalid secret file size",
			statusCode:     http.StatusUnauthorized,
			headers:        map[string]string{wwwAuthenticateHeaderName: "Basic realm=" + filepath.Join(testCaseFilePath, "secret.key")},
			expectedError:  "invalid secret file size",
			platform:       runtime.GOOS,
			createMockFile: true,
		},
		{
			name:           "token request fail",
			statusCode:     http.StatusUnauthorized,
			headers:        map[string]string{wwwAuthenticateHeaderName: "Basic realm=" + filepath.Join(testCaseFilePath, "secret.key")},
			expectedError:  "error creating http request net/http: nil Context",
			platform:       runtime.GOOS,
			createMockFile: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.platform+" "+tc.name, func(t *testing.T) {
			if tc.platform != "linux" && tc.platform != "windows" && tc.platform != "testPlatform" {
				t.Skip("Skipping test because current platform is not linux or windows")
			}

			unsetEnvVars()
			setEnvVars(t, AzureArc)

			response := &http.Response{
				StatusCode: tc.statusCode,
				Header:     make(http.Header),
			}

			for k, v := range tc.headers {
				response.Header.Set(k, v)
			}

			if tc.createMockFile {
				expectedFilePath := filepath.Join(testCaseFilePath)
				mockFilePath := filepath.Join(expectedFilePath, "secret.key")
				supportedAzureArcPlatforms[tc.platform] = expectedFilePath

				if tc.name == "Invalid secret file size" {
					createMockFile(t, mockFilePath, 5000)
				} else {
					createMockFile(t, mockFilePath, 0)
				}

				defer os.Remove(mockFilePath)
			}

			contextToUse := context.Background()
			client := &Client{}

			if tc.name == "token request fail" {
				contextToUse = nil
			}

			_, err := client.handleAzureArcResponse(contextToUse, response, "", tc.platform)

			if err == nil || err.Error() != tc.expectedError {
				t.Fatalf("expected error %v, got %v", tc.expectedError, err)
			}
		})
	}
}
