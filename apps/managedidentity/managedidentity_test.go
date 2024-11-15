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
	for _, testCase := range []Source{AzureArc, DefaultToIMDS} {
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
		if err == nil {
			t.Fatal(`expected error: azure arc not supported error"`)

		}
		if err.Error() != "azure Arc doesn't support user assigned managed identities" {
			t.Fatalf(`expected error: azure arc not supported error, got error: "%v"`, err)
		}

	}
}
func TestAzureArcPlatformSupported(t *testing.T) {
	setEnvVars(t, AzureArc)
	setCustomAzureArcFilePath(t, fakeAzureArcFilePath)
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
