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
	"os"
	"strings"
	"testing"
	"time"

	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
)

const (
	// Resources
	resource              = "https://management.azure.com"
	resourceDefaultSuffix = "https://management.azure.com/.default"

	// Endpoints
	imdsEndpoint          = "http://169.254.169.254/metadata/identity/oauth2/token"
	azureArcEndpoint      = "http://localhost:40342/metadata/identity/oauth2/token"
	appServiceEndpoint    = "http://127.0.0.1:41564/msi/token"
	cloudShellEndpoint    = "http://localhost:40342/metadata/identity/oauth2/token"
	serviceFabricEndpoint = "http://localhost:40342/metadata/identity/oauth2/token"
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
	StatusCode    string `json:"statusCode"`
	Message       string `json:"message"`
	CorrelationID string `json:"correlationId,omitempty"`
}

// TODO: Reenable as needed
// type CloudShellErrorResponse struct {
// 	Error struct {
// 		Code    string `json:"code"`
// 		Message string `json:"message"`
// 	} `json:"error"`
// }

type fakeClient struct{}
type errorClient struct{}

func fakeMIClient(mangedIdentityId ID, options ...ClientOption) (Client, error) {
	fakeClient, err := New(mangedIdentityId, options...)

	if err != nil {
		return Client{}, err
	}

	return fakeClient, nil
}

func (*fakeClient) CloseIdleConnections() {}

func (*fakeClient) Do(req *http.Request) (*http.Response, error) {
	w := http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(getSuccessfulResponse(resource))),
		Header:     make(http.Header),
	}
	return &w, nil
}

func (*errorClient) Do(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf(getMsiErrorResponse())
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

func getMsiErrorResponse() string {
	response := ErrorResponse{
		StatusCode:    "500",
		Message:       "An unexpected error occurred while fetching the AAD Token.",
		CorrelationID: "7d0c9763-ff1d-4842-a3f3-6d49e64f4513",
	}
	jsonResponse, _ := json.Marshal(response)
	return string(jsonResponse)
}

// TODO: Reenable as needed
// func getMsiErrorResponseCloudShell() string {
// 	response := CloudShellErrorResponse{}
// 	response.Error.Code = "AudienceNotSupported"
// 	response.Error.Message = "Audience user.read is not a supported MSI token audience."
// 	jsonResponse, _ := json.Marshal(response)
// 	return string(jsonResponse)
// }

func getMsiErrorResponseNoRetry() string {
	response := ErrorResponse{
		StatusCode:    "123",
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

func expectedRequest(source Source, resource string) (*http.Request, error) {
	return expectedRequestWithId(source, resource, SystemAssigned())
}

func expectedRequestWithId(source Source, resource string, id ID) (*http.Request, error) {
	var endpoint string
	headers := http.Header{}
	queryParameters := make(map[string][]string)
	// bodyParameters := make(map[string][]string)

	switch source {
	case DefaultToIMDS:
		endpoint = imdsEndpoint
		queryParameters["api-version"] = []string{"2018-02-01"}
		queryParameters["resource"] = []string{resource}
		headers.Add("Metadata", "true")
	case AzureArc:
		endpoint = azureArcEndpoint
		queryParameters["api-version"] = []string{"2019-11-01"}
		queryParameters["resource"] = []string{resource}
		headers.Add("Metadata", "true")
		// TODO: Reenable as needed
		// case APP_SERVICE:
		//     endpoint = appServiceEndpoint
		//     queryParameters["api-version"] = []string{"2019-08-01"}
		//     queryParameters["resource"] = []string{resource}
		//     headers["X-IDENTITY-HEADER"] = "secret"
		// case CLOUD_SHELL:
		//     endpoint = cloudShellEndpoint
		//     headers["ContentType"] = "application/x-www-form-urlencoded"
		//     headers["Metadata"] = "true"
		//     bodyParameters["resource"] = []string{resource}
		//     queryParameters["resource"] = []string{resource}
		//     return HttpRequest{
		//         Method:  "GET",
		//         URL:     computeUri(endpoint, queryParameters),
		//         Headers: headers,
		//         Body:    url.Values(bodyParameters).Encode(),
		//     }
		// case SERVICE_FABRIC:
		//     endpoint = serviceFabricEndpoint
		//     queryParameters["api-version"] = []string{"2019-07-01-preview"}
		//     queryParameters["resource"] = []string{resource}
	}

	switch id.(type) {
	case ClientID:
		queryParameters[MIQueryParameterClientId] = []string{id.value()}
	case ResourceID:
		queryParameters[MIQueryParameterResourceId] = []string{id.value()}
	case ObjectID:
		queryParameters[MIQueryParameterObjectId] = []string{id.value()}
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

// The following structs are used for creating data sources, similar to Javas @ParameterizedTest
type sourceTestData struct {
	source         Source
	endpoint       string
	expectedSource Source
}

type resourceTestData struct {
	source   Source
	endpoint string
	resource string
}

func createDataGetSource() []sourceTestData {
	return []sourceTestData{
		{source: AzureArc, endpoint: azureArcEndpoint, expectedSource: AzureArc},
		{source: AppService, endpoint: appServiceEndpoint, expectedSource: AppService},
		{source: CloudShell, endpoint: cloudShellEndpoint, expectedSource: CloudShell},
		{source: DefaultToIMDS, endpoint: imdsEndpoint, expectedSource: DefaultToIMDS},
		{source: DefaultToIMDS, endpoint: "", expectedSource: DefaultToIMDS},
		{source: ServiceFabric, endpoint: serviceFabricEndpoint, expectedSource: ServiceFabric},
	}
}

func createResourceData() []resourceTestData {
	return []resourceTestData{
		{source: AppService, endpoint: appServiceEndpoint, resource: resource},
		{source: AppService, endpoint: appServiceEndpoint, resource: resourceDefaultSuffix},
		{source: CloudShell, endpoint: cloudShellEndpoint, resource: resource},
		{source: CloudShell, endpoint: cloudShellEndpoint, resource: resourceDefaultSuffix},
		{source: AzureArc, endpoint: azureArcEndpoint, resource: resource},
		{source: AzureArc, endpoint: azureArcEndpoint, resource: resourceDefaultSuffix},
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resource},
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resourceDefaultSuffix},
		{source: DefaultToIMDS, endpoint: "", resource: resource},
		{source: ServiceFabric, endpoint: serviceFabricEndpoint, resource: resource},
		{source: ServiceFabric, endpoint: serviceFabricEndpoint, resource: resourceDefaultSuffix},
	}
}

type mockEnvironmentVariables struct {
	vars map[string]string
}

func setEnvVars(source Source) {
	switch source {
	case AzureArc:
		os.Setenv(IdentityEndpointEnvVar, "some_value")
		os.Setenv(IMDSEnvVar, "some_value")
	case AppService:
		os.Setenv(IdentityEndpointEnvVar, "some_value")
		os.Setenv(IdentityHeaderEnvVar, "some_value")
	case CloudShell:
		os.Setenv(MsiEndpointEnvVar, "some_value")
	case ServiceFabric:
		os.Setenv(IdentityEndpointEnvVar, "some_value")
		os.Setenv(IdentityHeaderEnvVar, "some_value")
		os.Setenv(IdentityServerThumbprintEnvVar, "some_value")
	}
}

func unsetEnvVars() {
	os.Unsetenv(IdentityEndpointEnvVar)
	os.Unsetenv(IdentityHeaderEnvVar)
	os.Unsetenv(IdentityServerThumbprintEnvVar)
	os.Unsetenv(IMDSEnvVar)
	os.Unsetenv(MsiEndpointEnvVar)
}

func environmentVariablesHelper(source Source, endpoint string) *mockEnvironmentVariables {
	vars := map[string]string{
		"SourceType": source.String(),
	}

	switch source {
	case AppService:
		vars[IdentityEndpointEnvVar] = endpoint
		vars[IdentityHeaderEnvVar] = "secret"
	case DefaultToIMDS:
		vars[IMDSEnvVar] = endpoint
	case ServiceFabric:
		vars[IdentityEndpointEnvVar] = endpoint
		vars[IdentityHeaderEnvVar] = "secret"
		vars[IdentityServerThumbprintEnvVar] = "thumbprint"
	case CloudShell:
		vars[MsiEndpointEnvVar] = endpoint
	case AzureArc:
		vars[IdentityEndpointEnvVar] = endpoint
		vars[IMDSEnvVar] = endpoint
	}

	return &mockEnvironmentVariables{vars: vars}
}

// TODO: Fill in as needed
func Test_Get_Source(t *testing.T) {
	// add reset source type
	testCases := createDataGetSource()

	for _, testCase := range testCases {
		t.Run(testCase.source.String(), func(t *testing.T) {
			unsetEnvVars()
			setEnvVars(testCase.source)

			fakeHTTPClient := fakeClient{}
			client, err := fakeMIClient(SystemAssigned(), WithHTTPClient(&fakeHTTPClient))
			if err != nil {
				t.Fatal(err)
			}

			actualSource := GetSource(client)

			if actualSource != testCase.expectedSource {
				t.Errorf("expected %v, got %v", testCase.expectedSource, actualSource)
			}
		})
	}
}

// TODO: Fill in as needed
func Test_SystemAssigned_Returns_Token_Success(t *testing.T) {
	// Set envVars correct
	// Use createResourceData correctly when all sources are working
	// TODO: Add assertions for result, token not being null
	// TODO: Add assertions for token source provider and result.metadata token source being equal
	// TODO: Same as above but also call again and confirm TokenSource.Cache and metadata tokenSource are equal
	// assertNotNull(result.accessToken());
	// String accessToken = result.accessToken();
	// result = miApp.acquireTokenForManagedIdentity(
	//         ManagedIdentityParameters.builder(resource)
	//                 .build()).get();
	// assertNotNull(result.accessToken());
	// assertEquals(accessToken, result.accessToken());
	// verify(httpClientMock, times(1)).send(any());
	testCases := createResourceData()

	for _, testCase := range testCases {
		t.Run(testCase.source.String(), func(t *testing.T) {
			unsetEnvVars()
			setEnvVars(testCase.source)

			fakeHTTPClient := fakeClient{}
			client, err := fakeMIClient(SystemAssigned(), WithHTTPClient(&fakeHTTPClient))

			if err != nil {
				t.Fatal(err)
			}

			result, err := client.AcquireToken(context.Background(), "fakeresource")

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

// TODO: Fill in as needed
func Test_UserAssigned_Returns_Token_Success(t *testing.T) {
	// Set environment variables
	// Assert.IsNotNull(result);
	// Assert.IsNotNull(result.AccessToken);
	// Assert.AreEqual(TokenSource.IdentityProvider, result.AuthenticationResultMetadata.TokenSource);

	// Do second call
	// Assert.IsNotNull(result);
	// Assert.IsNotNull(result.AccessToken);
	// Assert.AreEqual(TokenSource.Cache, result.AuthenticationResultMetadata.TokenSource);
}

// TODO: Fill in as needed
func Test_UserAssigned_Returns_NotSupported(t *testing.T) {
	// Assert.IsNotNull(result);
	// Assert.IsNotNull(result.AccessToken);
	// Assert.AreEqual(TokenSource.IdentityProvider, result.AuthenticationResultMetadata.TokenSource);

	// Acquire token for same scope
	// Assert.IsNotNull(result);
	// Assert.IsNotNull(result.AccessToken);
	// Assert.AreEqual(TokenSource.Cache, result.AuthenticationResultMetadata.TokenSource);

	// Acquire token for different scope
	// Assert.IsNotNull(result);
	// Assert.IsNotNull(result.AccessToken);
	// Assert.AreEqual(TokenSource.IdentityProvider, result.AuthenticationResultMetadata.TokenSource);
}

// TODO: Fill in as needed
func Test_DifferentScopes_Requests_NewToken(t *testing.T) {
	// Make a acquireTokenForManagedIdentity call
	// assertNotNull(result.accessToken());
	// Using same miApp, make another acquireTokenForManagedIdentity call
	// assertNotNull(result.accessToken());
	// verify was called twice
	// Assert token source to check the token source is IDP and not Cache.
}

// TODO: Fill in as needed
func Test_Wrong_Scopes(t *testing.T) {
	// SystemAssigned
	// Config.AccessorOptions = null, disabling shared cache options to avoid cross test pollution

	// Assert.IsNotNull('This would be the returned error message');
	// Assert.True('errorMessage contains same managedIdentitySource');
	// Assert.True('errorMessage contains errors.MiErrorCodeRequestFailed');
	// Assert.IsFalse(errorMessage.Contains(errors.ManagedIdentityUnexpectedErrorResponse));
}

// TODO: Fill in as needed
func Test_Retry(t *testing.T) {
	// Assert.IsNotNull(errorMessage);
	// Assert.True('errorMessage contains MsalError.MiErrorCodeRequestFailed');
	// Assert.True('errorMessage contains same managedIdentitySource');
	// Assert.True('errorMessage contains IsRetryable');
}

// TODO: Fill in as needed
func Test_Request_Failed_NoPayload(t *testing.T) {
	// Assert.IsNotNull(errorMessage);
	// Assert.True('errorMessage contains same managedIdentitySource');
	// Assert.True('errorMessage contains errors.MiErrorCodeRequestFailed');
	// Assert.True('errorMessage contains errors.ManagedIdentityNoResponseReceived');
}

// TODO: Fill in as needed
func Test_Request_Failed_NullResponse(t *testing.T) {
	// Assert.IsNotNull(errorMessage);
	// Assert.True('errorMessage contains same managedIdentitySource');
	// Assert.True('errorMessage contains errors.MiErrorCodeRequestFailed');
	// Assert.True('errorMessage contains errors.ManagedIdentityInvalidResponse');
}

// TODO: Fill in as needed
func Test_Request_Failed_UnreachableNetwork(t *testing.T) {
	// Assert.IsNotNull(errorMessage);
	// Assert.True('errorMessage contains same managedIdentitySource');
	// Assert.True('errorMessage contains errors.MiErrorCodeUnreachableNetwork');
	// Assert.True('errorMessage contains "A socket operation was attempted to an unreachable network."');
}

// TODO: Fill in as needed
func Test_AzureArc_MissingAuthHeader(t *testing.T) {
	// From java test azureArcManagedIdentity_MissingAuthHeader
	// Use AzureArc source
	// Set http response to 401
	// Error message should be returned from acquireTokenForManagedIdentity call
	// Assert.IsNotNull(errorMessage);
	// Assert.True('errorMessage contains managedIdentitySource is azureArc);
	// Assert.True('errorMessage contains errors.MiErrorCodeRequestFailed);
	// Assert.True('errorMessage contains errors.ManagedIdentityNoChallengeError);
}

// TODO: Fill in as needed
func Test_AzureArc_InvalidAuthHeader(t *testing.T) {
	// From java test azureArcManagedIdentity_InvalidAuthHeader
	// Use AzureArc source
	// Set http response to 401
	// response.headers().put("WWW-Authenticate", Collections.singletonList("xyz"));
	// Error message should be returned from acquireTokenForManagedIdentity call
	// Assert.IsNotNull(errorMessage);
	// Assert.True(managedIdentitySource is azureArc, 'errorMessage contains same source');
	// Assert.True('errorMessage contains errors.MiErrorCodeRequestFailed);
	// Assert.True('errorMessage contains errors.ManagedIdentityInvalidChallenge);
}

// TODO: Fill in as needed
func Test_AzureArc_AuthHeader_Validation(t *testing.T) {
	// From java test azureArcManagedIdentityAuthheaderValidationTest
	// Use AzureArc source
	// Set http response to 401
	// response.headers().put("WWW-Authenticate", Collections.singletonList("Basic realm=" + validPathWithMissingFile));
	// Both a missing file and an invalid path structure should throw an exception
	// Path validPathWithMissingFile = Paths.get(System.getenv("ProgramData")+ "/AzureConnectedMachineAgent/Tokens/secret.key");
	// Path invalidPathWithRealFile = Paths.get(this.getClass().getResource("/msi-azure-arc-secret.txt").toURI());
	// Error message should be returned from acquireTokenForManagedIdentity call
	// Assert.IsNotNull(errorMessage);
	// Assert.True(managedIdentitySource is azureArc, 'errorMessage contains same source');
	// Assert.True('errorMessage contains errors.ManagedIdentityInvalidFilePath);
	//response.headers().put("WWW-Authenticate", Collections.singletonList("Basic realm=" + invalidPathWithRealFile));
	// Do acquireTokenForManagedIdentity call again
	// Assert.True('errorMessage contains errors.ManagedIdentityInvalidFilePath);
}

// TODO: Fill in as needed
func Test_Cache(t *testing.T) {
	// Disabled shared cache options to avoid cross test pollution

	// Following are from .Net test ManagedIdentityCacheTestAsync
	// Assert.AreEqual(ManagedIdentityDefaultTenant, args.RequestTenantId);
	// Assert.AreEqual(ManagedIdentityDefaultClientId, args.ClientId);
	// Assert.IsNull(args.Account);
	// Assert.IsTrue(args.IsApplicationCache);
	// Assert.AreEqual(cancellationToken, args.CancellationToken);
	// appTokenCacheRecoder.AssertAccessCounts(1, 1);
}

// TODO: Fill in as needed
func Test_Shared_Cache(t *testing.T) {
	// Create 2 instances of miApp
	// acquireTokenForManagedIdentity on first
	// assertNotNull(resultMiApp1.accessToken());
	// acquireTokenForManagedIdentity on second
	// assertNotNull(resultMiApp2.accessToken());

	// acquireTokenForManagedIdentity does a cache lookup by default, and all ManagedIdentityApplication's share a cache,
	// so calling acquireTokenForManagedIdentity with the same parameters in two different ManagedIdentityApplications
	// should return the same token
	//assertEquals(resultMiApp1.accessToken(), resultMiApp2.accessToken())
	//verify(httpClientMock, times(1)).send(any())
}

// TODO: Fill in as needed
func Test_Expires(t *testing.T) {
	// From .NET test ManagedIdentityExpiresOnTestAsync
	// Assert.IsNotNull(AuthResult);
	// Assert.IsNotNull(AuthResult.AccessToken);
	// Assert.Equals(TokenSource.IdentityProvider, AuthResult.AuthenticationResultMetadata.TokenSource);
	// Assert.Equals(ApiEvent.ApiIds.AcquireTokenForSystemAssignedManagedIdentity, builder.CommonParameters.ApiId);
	// Assert.Equals(refreshOnHasValue, result.AuthenticationResultMetadata.RefreshOn.HasValue);
}

// TODO: Fill in as needed
func Test_Invalid_RefreshOn(t *testing.T) {
	// Check MsalClientException message
}

// TODO: Fill in as needed
func Test_Is_Proactively_Refreshed(t *testing.T) {
	// From .NET test ManagedIdentityIsProactivelyRefreshedAsync
	// Trace.WriteLine("1. Setup an app with a token cache with one AT");
	// Trace.WriteLine("2. Configure AT so that it shows it needs to be refreshed");
	// Trace.WriteLine("3. Configure MSI to respond with a valid token");
	// Trace.WriteLine("4. ATM - should perform an RT refresh");

	// Assert.IsNotNull(AcquireTokenForManagedIdentity result);
	// Assert.AreEqual(0, httpManager.QueueSize,
	//     "MSAL should have refreshed the token because the original AT was marked for refresh");
	// cacheAccess.WaitTo_AssertAcessCounts(1, 1);
	// Assert.AreEqual(CacheRefreshReason.ProactivelyRefreshed, result.AuthenticationResultMetadata.CacheRefreshReason);
	// Assert.AreEqual(refreshOn, result.AuthenticationResultMetadata.RefreshOn);
	// Assert.AreEqual(CacheRefreshReason.NotApplicable, result.AuthenticationResultMetadata.CacheRefreshReason);
}

// TODO: Fill in as needed
func Test_Proactive_Refresh_Cancel_Success(t *testing.T) {
	// From .NET test ProactiveRefresh_CancelsSuccessfully_Async
	// Assert.IsTrue(TestCommon.YieldTillSatisfied(() => wasErrorLogged));
	// void LocalLogCallback(LogLevel level, string message, bool containsPii)
	// {
	//     if (level == LogLevel.Warning &&
	//         message.Contains(SilentRequestHelper.ProactiveRefreshCancellationError))
	//     {
	//         wasErrorLogged = true;
	//     }
	// }
}

// TODO: Fill in as needed
func Test_ParallelRequests_CallTokenEndpointOnce(t *testing.T) {
	// From .NET test ParallelRequests_CallTokenEndpointOnceAsync
	// Assert.IsTrue(identityProviderHits == 1);
	// Assert.IsTrue(cacheHits == 9);
}

// TODO: Fill in as needed
func Test_EmptyOrNull_Scope(t *testing.T) {
	// Use no scope
	// Check for ArgumentNull message
}

// TODO: Fill in as needed
func Test_CancelledRequest_Returns_Error(t *testing.T) {
	// Check for TaskCanceledException message
}
