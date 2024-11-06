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
	t.Cleanup(func() { os.Remove(path) })
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
	testCases := []struct {
		name   string
		source Source
	}{
		{
			name:   "testAzureArcSystemAssigned",
			source: AzureArc,
		},
		{
			name:   "testAzureArcUserClientAssigned",
			source: AzureArc,
		},
		{
			name:   "testAzureArcUserResourceAssigned",
			source: AzureArc,
		},
		{
			name:   "testAzureArcUserObjectAssigned",
			source: AzureArc,
		},
		{
			name:   "testDefaultToImds",
			source: DefaultToIMDS,
		},
		{
			name:   "testDefaultToImdsClientAssigned",
			source: DefaultToIMDS,
		},
		{
			name:   "testDefaultToImdsResourceAssigned",
			source: DefaultToIMDS,
		},
		{
			name:   "testDefaultToImdsObjectAssigned",
			source: DefaultToIMDS,
		},
		{
			name:   "testDefaultToImdsEmptyEndpoint",
			source: DefaultToIMDS,
		},
		{
			name:   "testDefaultToImdsLinux",
			source: DefaultToIMDS,
		},
		{
			name:   "testDefaultToImdsEmptyEndpointLinux",
			source: DefaultToIMDS,
		},
	}
	for _, testCase := range testCases {
		t.Run(string(testCase.source), func(t *testing.T) {
			unsetEnvVars(t)
			setEnvVars(t, testCase.source)
			setCustomAzureArcFilePath(t, fakeAzureArcFilePath)

			actualSource, err := GetSource()
			if err != nil {
				t.Fatalf("error while getting source: %s", err.Error())
			}
			if actualSource != testCase.source {
				t.Errorf(errorExpectedButGot, testCase.source, actualSource)
			}
		})
	}
}

func TestAzureArcReturnsWhenHimdsFound(t *testing.T) {
	unsetEnvVars(t)
	mockFilePath := filepath.Join(t.TempDir(), "himds")
	setCustomAzureArcFilePath(t, mockFilePath)

	// Create the mock himds file
	createMockFile(t, mockFilePath, 1024)

	// Ensure file is deleted after test
	t.Cleanup(func() {
		if err := os.Remove(mockFilePath); err != nil {
			t.Fatalf("failed to delete mock file: %s", err)
		}
	})

	actualSource, err := GetSource()
	if err != nil {
		t.Fatalf("error while getting source: %s", err.Error())
	}

	if actualSource != AzureArc {
		t.Errorf(errorExpectedButGot, AzureArc, actualSource)
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

func TestAzureArcAcquireTokenReturnsToken(t *testing.T) {
	testCaseFilePath := getMockFilePath(t)
	type ArcRequest struct {
		name           string
		headers        map[string]string
		expectedError  string
		platform       string
		createMockFile bool
		shouldFail     bool
	}
	testCases := []struct {
		resource string
		miType   ID
		request  ArcRequest
	}{
		{resource: resource, miType: SystemAssigned(), request: ArcRequest{
			name:          "No www-authenticate header",
			headers:       map[string]string{},
			expectedError: "response has no www-authenticate header",
			platform:      runtime.GOOS,
			shouldFail:    true,
		}},
		{resource: resource, miType: SystemAssigned(), request: ArcRequest{
			name:          "Basic realm= not found",
			headers:       map[string]string{wwwAuthenticateHeaderName: "Basic "},
			expectedError: "basic realm= not found in the string, instead found: Basic ",
			platform:      runtime.GOOS,
			shouldFail:    true,
		}},
		{resource: resource, miType: SystemAssigned(), request: ArcRequest{
			name:          "Platform not supported",
			headers:       map[string]string{wwwAuthenticateHeaderName: "Basic realm=/path/to/secret.key"},
			expectedError: "platform not supported, expected linux or windows",
			platform:      "freebsd",
			shouldFail:    true,
		}},
		{resource: resource, miType: SystemAssigned(), request: ArcRequest{
			name:           "Invalid file extension",
			headers:        map[string]string{wwwAuthenticateHeaderName: "Basic realm=/path/to/secret.txt"},
			expectedError:  "invalid file extension, expected .key, got .txt",
			platform:       runtime.GOOS,
			createMockFile: true,
			shouldFail:     true,
		}},
		{resource: resource, miType: SystemAssigned(), request: ArcRequest{
			name:           "Invalid file path",
			headers:        map[string]string{wwwAuthenticateHeaderName: "Basic realm=" + filepath.Join("path", "to", "secret.key")},
			expectedError:  "invalid file path, expected " + testCaseFilePath + ", got " + filepath.Join("path", "to"),
			platform:       runtime.GOOS,
			createMockFile: true,
			shouldFail:     true,
		}},
		{resource: resource, miType: SystemAssigned(), request: ArcRequest{
			name:    "Unable to get file info",
			headers: map[string]string{wwwAuthenticateHeaderName: basicRealm + filepath.Join(testCaseFilePath, wrongSecretKey)},
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
		{resource: resource, miType: SystemAssigned(), request: ArcRequest{
			name:           "Invalid secret file size",
			headers:        map[string]string{wwwAuthenticateHeaderName: basicRealm + filepath.Join(testCaseFilePath, secretKey)},
			expectedError:  "invalid secret file size, expected 4096, file size was 5000",
			platform:       runtime.GOOS,
			createMockFile: true,
			shouldFail:     true,
		}},
		{resource: resourceDefaultSuffix, miType: SystemAssigned(),
			request: ArcRequest{
				name:           "success",
				headers:        map[string]string{wwwAuthenticateHeaderName: basicRealm + filepath.Join(testCaseFilePath, secretKey)},
				expectedError:  "",
				platform:       runtime.GOOS,
				createMockFile: true,
				shouldFail:     false,
			}},
		{resource: resourceDefaultSuffix, miType: UserAssignedClientID("Clientid"),
			request: ArcRequest{
				name:           "Platform not supported",
				headers:        map[string]string{wwwAuthenticateHeaderName: basicRealm + filepath.Join(testCaseFilePath, secretKey)},
				expectedError:  "azure Arc doesn't support user assigned managed identities",
				platform:       runtime.GOOS,
				createMockFile: true,
				shouldFail:     true,
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
			if testCase.request.platform == "freebsd" {
				setCustomAzureArcPlatformPath(t, "")
			} else {
				setCustomAzureArcPlatformPath(t, testCaseFilePath)
			}
			if testCase.request.name == "Invalid secret file size" {
				createMockFile(t, mockFilePath, 5000)
			} else {
				createMockFile(t, mockFilePath, 0)
			}

			headers := http.Header{}
			for k, v := range testCase.request.headers {
				headers.Set(k, v)
			}
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

			client, err := New(testCase.miType, WithHTTPClient(&mockClient))
			if err != nil {
				if testCase.request.shouldFail {
					if err.Error() != testCase.request.expectedError {
						t.Fatalf(`expected error: "%v" got error: "%v"`, testCase.request.expectedError, err)
					}
					return
				} else {
					t.Fatal(err)
				}
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

			if query.Get(apiVersionQueryParameterName) != azureArcAPIVersion {
				t.Fatalf("api-version not on %s got %s", azureArcAPIVersion, query.Get(apiVersionQueryParameterName))
			}
			if query.Get(resourceQueryParameterName) != strings.TrimSuffix(testCase.resource, "/.default") {
				t.Fatal("suffix /.default was not removed.")
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
