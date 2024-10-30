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

	// Write the content to the file
	if _, err := f.WriteString("secret file data"); err != nil {
		t.Fatalf("failed to write to file: %v", err)
	}
}

func getMockFilePath(t *testing.T) string {
	tempDir := t.TempDir()
	return filepath.Join(tempDir, "AzureConnectedMachineAgent")
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

	unsetEnvVars(t)
	// Get system dependent mock file path
	var mockFilePath string
	if runtime.GOOS == "windows" {
		mockFilePath = filepath.Join(os.TempDir(), "himds.exe")
	} else {
		mockFilePath = filepath.Join("/tmp", "himds")
	}
	setCustomAzureArcFilePath(t, mockFilePath)

	// Create the mock himds file
	createMockFile(t, mockFilePath, 1024)

	// Ensure file is deleted after test
	t.Cleanup(func() {
		if err := os.Remove(mockFilePath); err != nil {
			t.Fatalf("failed to delete mock file: %s", err)
		}
	})

	actualSource, err := GetSource(SystemAssigned())
	if err != nil {
		t.Fatalf("error while getting source: %s", err.Error())
	}

	if actualSource != AzureArc {
		t.Errorf(errorExpectedButGot, AzureArc, actualSource)
	}
}

func TestIMDSAcquireTokenReturnsTokenSuccess(t *testing.T) {
	testCases := []struct {
		resource   string
		miType     ID
		apiVersion string
	}{
		{resource: resource, miType: SystemAssigned(), apiVersion: imdsAPIVersion},
		{resource: resourceDefaultSuffix, miType: SystemAssigned(), apiVersion: imdsAPIVersion},
		{resource: resource, miType: UserAssignedClientID("clientId"), apiVersion: imdsAPIVersion},
		{resource: resourceDefaultSuffix, miType: UserAssignedResourceID("resourceId"), apiVersion: imdsAPIVersion},
		{resource: resourceDefaultSuffix, miType: UserAssignedObjectID("objectId"), apiVersion: imdsAPIVersion},
	}
	for _, testCase := range testCases {
		t.Run(string(DefaultToIMDS)+"-"+testCase.miType.value(), func(t *testing.T) {
			endpoint := imdsDefaultEndpoint
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
			if localUrl == nil || !strings.HasPrefix(localUrl.String(), endpoint) {
				t.Fatalf("url request is not on %s got %s", endpoint, localUrl)
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

func TestAzureArcAcquireTokenReturnsToken(t *testing.T) {
	testCaseFilePath := getMockFilePath(t)
	type ArcRequest struct {
		name           string
		statusCode     int
		headers        map[string]string
		expectedError  string
		platform       string
		createMockFile bool
		context        context.Context
		shouldFail     bool
	}
	testCases := []struct {
		resource   string
		miType     ID
		apiVersion string
		request    ArcRequest
	}{
		{resource: resource, miType: SystemAssigned(), apiVersion: azureArcAPIVersion, request: ArcRequest{
			name:          "No www-authenticate header",
			statusCode:    http.StatusUnauthorized,
			headers:       map[string]string{},
			expectedError: "response has no www-authenticate header",
			platform:      runtime.GOOS,
			shouldFail:    true,
		}},
		{resource: resource, miType: SystemAssigned(), apiVersion: azureArcAPIVersion, request: ArcRequest{
			name:          "Basic realm= not found",
			statusCode:    http.StatusUnauthorized,
			headers:       map[string]string{wwwAuthenticateHeaderName: "Basic "},
			expectedError: "basic realm= not found in the string, instead found: Basic ",
			platform:      runtime.GOOS,
			shouldFail:    true,
		}},
		{resource: resource, miType: SystemAssigned(), apiVersion: azureArcAPIVersion, request: ArcRequest{
			name:          "Platform not supported",
			statusCode:    http.StatusUnauthorized,
			headers:       map[string]string{wwwAuthenticateHeaderName: "Basic realm=/path/to/secret.key"},
			expectedError: "platform not supported, expected linux or windows",
			platform:      "platformNotSupported",
			context:       context.Background(),
			shouldFail:    true,
		}},
		{resource: resource, miType: SystemAssigned(), apiVersion: azureArcAPIVersion, request: ArcRequest{
			name:           "Invalid file extension",
			statusCode:     http.StatusUnauthorized,
			headers:        map[string]string{wwwAuthenticateHeaderName: "Basic realm=/path/to/secret.txt"},
			expectedError:  "invalid file extension, expected .key, got .txt",
			platform:       runtime.GOOS,
			createMockFile: true,
			shouldFail:     true,
		}},
		{resource: resource, miType: SystemAssigned(), apiVersion: azureArcAPIVersion, request: ArcRequest{
			name:           "Invalid file path",
			statusCode:     http.StatusUnauthorized,
			headers:        map[string]string{wwwAuthenticateHeaderName: "Basic realm=" + filepath.Join("path", "to", "secret.key")},
			expectedError:  "invalid file path, expected " + testCaseFilePath + ", got " + filepath.Join("path", "to"),
			platform:       runtime.GOOS,
			createMockFile: true,
			shouldFail:     true,
		}},
		{resource: resource, miType: SystemAssigned(), apiVersion: azureArcAPIVersion, request: ArcRequest{
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
			shouldFail:     true,
		}},
		{resource: resource, miType: SystemAssigned(), apiVersion: azureArcAPIVersion, request: ArcRequest{
			name:           "Invalid secret file size",
			statusCode:     http.StatusUnauthorized,
			headers:        map[string]string{wwwAuthenticateHeaderName: basicRealm + filepath.Join(testCaseFilePath, secretKey)},
			expectedError:  "invalid secret file size, expected 4096, file size was 5000",
			platform:       runtime.GOOS,
			createMockFile: true,
			shouldFail:     true,
		}},
		{resource: resourceDefaultSuffix, miType: SystemAssigned(), apiVersion: azureArcAPIVersion,
			request: ArcRequest{
				name:           "success",
				statusCode:     http.StatusUnauthorized,
				headers:        map[string]string{wwwAuthenticateHeaderName: basicRealm + filepath.Join(testCaseFilePath, secretKey)},
				expectedError:  "",
				platform:       runtime.GOOS,
				createMockFile: true,
				shouldFail:     false,
			}},
	}

	for _, testCase := range testCases {
		t.Run(string(testCase.request.name)+"-"+testCase.miType.value(), func(t *testing.T) {
			source := AzureArc
			endpoint := azureArcEndpoint
			unsetEnvVars(t)
			setEnvVars(t, source)
			setCustomAzureArcFilePath(t, fakeAzureArcFilePath)

			var localUrl *url.URL
			mockClient := mock.Client{}

			mockFilePath := filepath.Join(testCaseFilePath, secretKey)
			if testCase.request.platform != "platformNotSupported" {
				setCustomAzureArcPlatformPath(t, testCaseFilePath)
			}
			if testCase.request.name == "Invalid secret file size" {
				createMockFile(t, mockFilePath, 5000)
			} else {
				createMockFile(t, mockFilePath, 0)
			}

			t.Cleanup(func() { os.Remove(mockFilePath) })
			headers := http.Header{}
			for k, v := range testCase.request.headers {
				headers.Set(k, v)
			}
			mockClient.AppendResponse(mock.WithHTTPStatusCode(testCase.request.statusCode),
				mock.WithHTTPHeader(headers),
				mock.WithCallback(func(r *http.Request) {
					localUrl = r.URL
				}))

			responseBody, err := getSuccessfulResponse(resource)
			if err != nil {
				t.Fatalf(errorFormingJsonResponse, err.Error())
			}

			mockClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusUnauthorized), mock.WithHTTPHeader(headers),
				mock.WithBody(responseBody), mock.WithCallback(func(r *http.Request) {
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

			if testCase.request.shouldFail {
				if err == nil || err.Error() != testCase.request.expectedError {
					t.Fatalf(`expected error: "%v" got error: "%v"`, testCase.request.expectedError, err)
				}
				return

			}
			if err != nil {
				t.Fatal(err)
			}

			if localUrl == nil || !strings.HasPrefix(localUrl.String(), endpoint) {
				t.Fatalf("url request is not on %s got %s", endpoint, localUrl)
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
	for _, id := range []ID{UserAssignedClientID("clientID"),
		UserAssignedResourceID("resourceID"),
		UserAssignedObjectID("objectID")} {
		t.Run(fmt.Sprintf("%T", id), func(t *testing.T) {
			unsetEnvVars(t)
			setEnvVars(t, AzureArc)
			_, err := New(id)
			if err == nil {
				t.Fatal("client New() should return a error but did not.")
			}
			if err.Error() != "azure Arc doesn't support user assigned managed identities" {
				t.Fatalf("expected error message 'azure Arc doesn't support user assigned managed identities', got %s", err.Error())
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
			platform:         runtime.GOOS,
			expectedResult:   false,
		},
		{
			name:           "Only imdsEndpoint provided",
			imdsEndpoint:   "endpoint",
			platform:       runtime.GOOS,
			expectedResult: false,
		},
		{
			name:           "No endpoints provided",
			platform:       runtime.GOOS,
			expectedResult: false,
		},
		{
			name:           "Platform not supported",
			platform:       "darwin",
			expectedResult: false,
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
