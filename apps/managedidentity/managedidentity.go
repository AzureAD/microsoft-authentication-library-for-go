// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/*
Package managedidentity provides a client for retrieval of Managed Identity applications.
The Managed Identity Client is used to acquire a token for managed identity assigned to
an azure resource such as Azure function, app service, virtual machine, etc. to acquire a token
without using credentials.
*/
package managedidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/storage"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/slog"
)

const (
	// DefaultToIMDS indicates that the source is defaulted to IMDS when no environment variables are set.
	DefaultToIMDS Source = "DefaultToIMDS"
	AzureArc      Source = "AzureArc"
	ServiceFabric Source = "ServiceFabric"
	CloudShell    Source = "CloudShell"
	AzureML       Source = "AzureML"
	AppService    Source = "AppService"

	// General request query parameter names
	metaHTTPHeaderName           = "Metadata"
	apiVersionQueryParameterName = "api-version"
	resourceQueryParameterName   = "resource"
	wwwAuthenticateHeaderName    = "www-authenticate"

	// UAMI query parameter name
	miQueryParameterClientId       = "client_id"
	miQueryParameterObjectId       = "object_id"
	miQueryParameterPrincipalId    = "principal_id"
	miQueryParameterResourceIdIMDS = "msi_res_id"
	miQueryParameterResourceId     = "mi_res_id"

	// IMDS
	imdsDefaultEndpoint           = "http://169.254.169.254/metadata/identity/oauth2/token"
	imdsAPIVersion                = "2018-02-01"
	systemAssignedManagedIdentity = "system_assigned_managed_identity"

	// Azure Arc
	azureArcEndpoint               = "http://127.0.0.1:40342/metadata/identity/oauth2/token"
	azureArcAPIVersion             = "2020-06-01"
	azureArcFileExtension          = ".key"
	azureArcMaxFileSizeBytes int64 = 4096
	linuxTokenPath                 = "/var/opt/azcmagent/tokens"
	linuxHimdsPath                 = "/opt/azcmagent/bin/himds"
	azureConnectedMachine          = "AzureConnectedMachineAgent"
	himdsExecutableName            = "himds.exe"
	tokenName                      = "Tokens"

	// App Service
	appServiceAPIVersion = "2019-08-01"

	// Environment Variables
	identityEndpointEnvVar              = "IDENTITY_ENDPOINT"
	identityHeaderEnvVar                = "IDENTITY_HEADER"
	azurePodIdentityAuthorityHostEnvVar = "AZURE_POD_IDENTITY_AUTHORITY_HOST"
	imdsEndVar                          = "IMDS_ENDPOINT"
	msiEndpointEnvVar                   = "MSI_ENDPOINT"
	msiSecretEnvVar                     = "MSI_SECRET"
	identityServerThumbprintEnvVar      = "IDENTITY_SERVER_THUMBPRINT"

	defaultRetryCount = 3
)

var retryCodesForIMDS = []int{
	http.StatusNotFound,                      // 404
	http.StatusGone,                          // 410
	http.StatusTooManyRequests,               // 429
	http.StatusInternalServerError,           // 500
	http.StatusNotImplemented,                // 501
	http.StatusBadGateway,                    // 502
	http.StatusServiceUnavailable,            // 503
	http.StatusGatewayTimeout,                // 504
	http.StatusHTTPVersionNotSupported,       // 505
	http.StatusVariantAlsoNegotiates,         // 506
	http.StatusInsufficientStorage,           // 507
	http.StatusLoopDetected,                  // 508
	http.StatusNotExtended,                   // 510
	http.StatusNetworkAuthenticationRequired, // 511
}

var retryStatusCodes = []int{
	http.StatusRequestTimeout,      // 408
	http.StatusTooManyRequests,     // 429
	http.StatusInternalServerError, // 500
	http.StatusBadGateway,          // 502
	http.StatusServiceUnavailable,  // 503
	http.StatusGatewayTimeout,      // 504
}

var getAzureArcPlatformPath = func(platform string) string {
	switch platform {
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), azureConnectedMachine, tokenName)
	case "linux":
		return linuxTokenPath
	default:
		return ""
	}
}

var getAzureArcHimdsFilePath = func(platform string) string {
	switch platform {
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), azureConnectedMachine, himdsExecutableName)
	case "linux":
		return linuxHimdsPath
	default:
		return ""
	}
}
var logOnce sync.Once

type Source string

type ID interface {
	value() string
}

type systemAssignedValue string // its private for a reason to make the input consistent.
type UserAssignedClientID string
type UserAssignedObjectID string
type UserAssignedResourceID string

func (s systemAssignedValue) value() string    { return string(s) }
func (c UserAssignedClientID) value() string   { return string(c) }
func (o UserAssignedObjectID) value() string   { return string(o) }
func (r UserAssignedResourceID) value() string { return string(r) }
func SystemAssigned() ID {
	return systemAssignedValue(systemAssignedManagedIdentity)
}

// cache never uses the client because instance discovery is always disabled.
var cacheManager *storage.Manager = storage.New(nil)

type Client struct {
	httpClient         ops.HTTPClient
	miType             ID
	source             Source
	authParams         authority.AuthParams
	retryPolicyEnabled bool
	logger             *slog.Logger
	piiLogging         bool
}

type ClientOptions struct {
	httpClient         ops.HTTPClient
	retryPolicyEnabled bool
	logger             *slog.Logger
	piiLogging         bool
}

type AcquireTokenOptions struct {
	claims string
}

type ClientOption func(o *ClientOptions)

type AcquireTokenOption func(o *AcquireTokenOptions)

// WithClaims sets additional claims to request for the token, such as those required by token revocation or conditional access policies.
// Use this option when Azure AD returned a claims challenge for a prior request. The argument must be decoded.
func WithClaims(claims string) AcquireTokenOption {
	return func(o *AcquireTokenOptions) {
		o.claims = claims
	}
}

// WithHTTPClient allows for a custom HTTP client to be set.
func WithHTTPClient(httpClient ops.HTTPClient) ClientOption {
	return func(o *ClientOptions) {
		o.httpClient = httpClient
	}
}

func WithRetryPolicyDisabled() ClientOption {
	return func(o *ClientOptions) {
		o.retryPolicyEnabled = false
	}
}

// Client to be used to acquire tokens for managed identity.
// ID: [SystemAssigned], [UserAssignedClientID], [UserAssignedResourceID], [UserAssignedObjectID]
//
// Options: [WithHTTPClient], [WithLogger]
func New(id ID, options ...ClientOption) (Client, error) {
	source, err := GetSource()
	if err != nil {
		return Client{}, err
	}

	// Check for user-assigned restrictions based on the source
	switch source {
	case AzureArc:
		switch id.(type) {
		case UserAssignedClientID, UserAssignedResourceID, UserAssignedObjectID:
			return Client{}, errors.New("Azure Arc doesn't support user-assigned managed identities")
		}
	case AzureML:
		switch id.(type) {
		case UserAssignedObjectID, UserAssignedResourceID:
			return Client{}, errors.New("Azure ML supports specifying a user-assigned managed identity by client ID only")
		}
	case CloudShell:
		switch id.(type) {
		case UserAssignedClientID, UserAssignedResourceID, UserAssignedObjectID:
			return Client{}, errors.New("Cloud Shell doesn't support user-assigned managed identities")
		}
	case ServiceFabric:
		switch id.(type) {
		case UserAssignedClientID, UserAssignedResourceID, UserAssignedObjectID:
			return Client{}, errors.New("Service Fabric API doesn't support specifying a user-assigned identity. The identity is determined by cluster resource configuration. See https://aka.ms/servicefabricmi")
		}
	}

	opts := ClientOptions{
		httpClient:         shared.DefaultClient,
		retryPolicyEnabled: true,
		logger:             slog.New(&slog.NopHandler{}),
		piiLogging:         false,
	}
	for _, option := range options {
		option(&opts)
	}

	switch t := id.(type) {
	case UserAssignedClientID:
		if len(string(t)) == 0 {
			return Client{}, fmt.Errorf("empty %T", t)
		}
	case UserAssignedResourceID:
		if len(string(t)) == 0 {
			return Client{}, fmt.Errorf("empty %T", t)
		}
	case UserAssignedObjectID:
		if len(string(t)) == 0 {
			return Client{}, fmt.Errorf("empty %T", t)
		}
	case systemAssignedValue:
	default:
		return Client{}, fmt.Errorf("unsupported type %T", id)
	}
	client := Client{
		miType:             id,
		httpClient:         opts.httpClient,
		retryPolicyEnabled: opts.retryPolicyEnabled,
		source:             source,
		logger:             opts.logger,
		piiLogging:         opts.piiLogging,
	}

	logOnce.Do(func() {
		client.logger.Log(context.Background(), slog.LevelInfo, "Managed Identity", slog.String("source", string(client.source)))
	})

	fakeAuthInfo, err := authority.NewInfoFromAuthorityURI("https://login.microsoftonline.com/managed_identity", false, true)
	if err != nil {
		return Client{}, err
	}
	client.authParams = authority.NewAuthParams(client.miType.value(), fakeAuthInfo)
	return client, nil
}

// GetSource detects and returns the managed identity source available on the environment.
func GetSource() (Source, error) {
	identityEndpoint := os.Getenv(identityEndpointEnvVar)
	identityHeader := os.Getenv(identityHeaderEnvVar)
	identityServerThumbprint := os.Getenv(identityServerThumbprintEnvVar)
	msiEndpoint := os.Getenv(msiEndpointEnvVar)
	msiSecret := os.Getenv(msiSecretEnvVar)
	imdsEndpoint := os.Getenv(imdsEndVar)

	if identityEndpoint != "" && identityHeader != "" {
		if identityServerThumbprint != "" {
			return ServiceFabric, nil
		}
		return AppService, nil
	} else if msiEndpoint != "" {
		if msiSecret != "" {
			return AzureML, nil
		} else {
			return CloudShell, nil
		}
	} else if isAzureArcEnvironment(identityEndpoint, imdsEndpoint) {
		return AzureArc, nil
	}

	return DefaultToIMDS, nil
}

// Acquires tokens from the configured managed identity on an azure resource.
//
// Resource: scopes application is requesting access to
// Options: [WithClaims]
func (c Client) AcquireToken(ctx context.Context, resource string, options ...AcquireTokenOption) (base.AuthResult, error) {
	resource = strings.TrimSuffix(resource, "/.default")
	o := AcquireTokenOptions{}
	for _, option := range options {
		option(&o)
	}
	c.authParams.Scopes = []string{resource}

	// when claims are empty, we get token from the cache, otherwise acquire a new one
	if o.claims == "" {
		storageTokenResponse, err := cacheManager.Read(ctx, c.authParams)
		if err != nil {
			return base.AuthResult{}, err
		}
		ar, err := base.AuthResultFromStorage(storageTokenResponse)
		if err == nil {
			ar.AccessToken, err = c.authParams.AuthnScheme.FormatAccessToken(ar.AccessToken)
			return ar, err
		}
	}
	switch c.source {
	case AzureArc:
		return c.acquireTokenForAzureArc(ctx, resource)
	case CloudShell:
		return c.acquireTokenForCloudShell(ctx, resource)
	case DefaultToIMDS:
		return c.acquireTokenForIMDS(ctx, resource)
	case AppService:
		return c.acquireTokenForAppService(ctx, resource)
	default:
		return base.AuthResult{}, fmt.Errorf("unsupported source %q", c.source)
	}
}

func (c Client) acquireTokenForAppService(ctx context.Context, resource string) (base.AuthResult, error) {
	req, err := createAppServiceAuthRequest(ctx, c.miType, resource)
	if err != nil {
		return base.AuthResult{}, err
	}
	tokenResponse, err := c.getTokenForRequest(req, resource)
	if err != nil {
		return base.AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

func (c Client) acquireTokenForIMDS(ctx context.Context, resource string) (base.AuthResult, error) {
	req, err := createIMDSAuthRequest(ctx, c.miType, resource)
	if err != nil {
		return base.AuthResult{}, err
	}
	tokenResponse, err := c.getTokenForRequest(req, resource)
	if err != nil {
		return base.AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

func (c Client) acquireTokenForCloudShell(ctx context.Context, resource string) (base.AuthResult, error) {
	req, err := createCloudShellAuthRequest(ctx, resource)
	if err != nil {
		return base.AuthResult{}, err
	}
	tokenResponse, err := c.getTokenForRequest(req, resource)
	if err != nil {
		return base.AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

func (c Client) acquireTokenForAzureArc(ctx context.Context, resource string) (base.AuthResult, error) {
	req, err := createAzureArcAuthRequest(ctx, resource, "")
	if err != nil {
		return base.AuthResult{}, err
	}

	response, err := c.httpClient.Do(req)
	if err != nil {
		return base.AuthResult{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusUnauthorized {
		return base.AuthResult{}, fmt.Errorf("expected a 401 response, received %d", response.StatusCode)
	}

	secret, err := c.getAzureArcSecretKey(response, runtime.GOOS)
	if err != nil {
		return base.AuthResult{}, err
	}

	secondRequest, err := createAzureArcAuthRequest(ctx, resource, string(secret))
	if err != nil {
		return base.AuthResult{}, err
	}

	tokenResponse, err := c.getTokenForRequest(secondRequest, resource)
	if err != nil {
		return base.AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

func authResultFromToken(authParams authority.AuthParams, token accesstokens.TokenResponse) (base.AuthResult, error) {
	if cacheManager == nil {
		return base.AuthResult{}, errors.New("cache instance is nil")
	}
	account, err := cacheManager.Write(authParams, token)
	if err != nil {
		return base.AuthResult{}, err
	}
	ar, err := base.NewAuthResult(token, account)
	if err != nil {
		return base.AuthResult{}, err
	}
	ar.AccessToken, err = authParams.AuthnScheme.FormatAccessToken(ar.AccessToken)
	return ar, err
}

// contains checks if the element is present in the list.
func contains[T comparable](list []T, element T) bool {
	for _, v := range list {
		if v == element {
			return true
		}
	}
	return false
}

// retry performs an HTTP request with retries based on the provided options.
func (c Client) retry(maxRetries int, req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	for attempt := 0; attempt < maxRetries; attempt++ {
		tryCtx, tryCancel := context.WithTimeout(req.Context(), time.Minute)
		c.logger.Log(tryCtx, slog.LevelInfo, "Managed Identity retrying request", slog.String("attempt", fmt.Sprint(attempt)))

		defer tryCancel()
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		cloneReq := req.Clone(tryCtx)
		resp, err = c.httpClient.Do(cloneReq)
		retryList := retryStatusCodes
		if c.source == DefaultToIMDS {
			retryList = retryCodesForIMDS
		}
		if err == nil && !contains(retryList, resp.StatusCode) {
			return resp, nil
		}
		select {
		case <-time.After(time.Second):
		case <-req.Context().Done():
			err = req.Context().Err()
			return resp, err
		}
	}
	return resp, err
}

func (c Client) getTokenForRequest(req *http.Request, resource string) (accesstokens.TokenResponse, error) {
	r := accesstokens.TokenResponse{}
	var resp *http.Response
	var err error

	if c.retryPolicyEnabled {
		resp, err = c.retry(defaultRetryCount, req)
	} else {
		resp, err = c.httpClient.Do(req)
	}
	if err != nil {
		return r, err
	}
	responseBytes, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return r, err
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted:
	default:
		sd := strings.TrimSpace(string(responseBytes))
		if sd != "" {
			return r, errors.CallErr{
				Req:  req,
				Resp: resp,
				Err: fmt.Errorf("http call(%s)(%s) error: reply status code was %d:\n%s",
					req.URL.String(),
					req.Method,
					resp.StatusCode,
					sd),
			}
		}
		return r, errors.CallErr{
			Req:  req,
			Resp: resp,
			Err:  fmt.Errorf("http call(%s)(%s) error: reply status code was %d", req.URL.String(), req.Method, resp.StatusCode),
		}
	}

	err = json.Unmarshal(responseBytes, &r)
	r.GrantedScopes.Slice = append(r.GrantedScopes.Slice, resource)

	return r, err
}

func createAppServiceAuthRequest(ctx context.Context, id ID, resource string) (*http.Request, error) {
	identityEndpoint := os.Getenv(identityEndpointEnvVar)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, identityEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-IDENTITY-HEADER", os.Getenv(identityHeaderEnvVar))
	q := req.URL.Query()
	q.Set("api-version", appServiceAPIVersion)
	q.Set("resource", resource)
	switch t := id.(type) {
	case UserAssignedClientID:
		q.Set(miQueryParameterClientId, string(t))
	case UserAssignedResourceID:
		q.Set(miQueryParameterResourceId, string(t))
	case UserAssignedObjectID:
		q.Set(miQueryParameterObjectId, string(t))
	case systemAssignedValue:
	default:
		return nil, fmt.Errorf("unsupported type %T", id)
	}
	req.URL.RawQuery = q.Encode()
	return req, nil
}

func createIMDSAuthRequest(ctx context.Context, id ID, resource string) (*http.Request, error) {
	msiEndpoint, err := url.Parse(imdsDefaultEndpoint)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse %q: %s", imdsDefaultEndpoint, err)
	}
	msiParameters := msiEndpoint.Query()
	msiParameters.Set(apiVersionQueryParameterName, imdsAPIVersion)
	msiParameters.Set(resourceQueryParameterName, resource)

	switch t := id.(type) {
	case UserAssignedClientID:
		msiParameters.Set(miQueryParameterClientId, string(t))
	case UserAssignedResourceID:
		msiParameters.Set(miQueryParameterResourceIdIMDS, string(t))
	case UserAssignedObjectID:
		msiParameters.Set(miQueryParameterObjectId, string(t))
	case systemAssignedValue: // not adding anything
	default:
		return nil, fmt.Errorf("unsupported type %T", id)
	}

	msiEndpoint.RawQuery = msiParameters.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, msiEndpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating http request %s", err)
	}
	req.Header.Set(metaHTTPHeaderName, "true")
	return req, nil
}

func createAzureArcAuthRequest(ctx context.Context, resource string, key string) (*http.Request, error) {
	identityEndpoint := os.Getenv(identityEndpointEnvVar)
	if identityEndpoint == "" {
		identityEndpoint = azureArcEndpoint
	}
	msiEndpoint, parseErr := url.Parse(identityEndpoint)

	if parseErr != nil {
		return nil, fmt.Errorf("couldn't parse %q: %s", identityEndpoint, parseErr)
	}

	msiParameters := msiEndpoint.Query()
	msiParameters.Set(apiVersionQueryParameterName, azureArcAPIVersion)
	msiParameters.Set(resourceQueryParameterName, resource)

	msiEndpoint.RawQuery = msiParameters.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, msiEndpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating http request %s", err)
	}
	req.Header.Set(metaHTTPHeaderName, "true")

	if key != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", key))
	}

	return req, nil
}

func isAzureArcEnvironment(identityEndpoint, imdsEndpoint string) bool {
	if identityEndpoint != "" && imdsEndpoint != "" {
		return true
	}
	himdsFilePath := getAzureArcHimdsFilePath(runtime.GOOS)
	if himdsFilePath != "" {
		if _, err := os.Stat(himdsFilePath); err == nil {
			return true
		}
	}
	return false
}

func (c *Client) getAzureArcSecretKey(response *http.Response, platform string) (string, error) {
	wwwAuthenticateHeader := response.Header.Get(wwwAuthenticateHeaderName)

	if len(wwwAuthenticateHeader) == 0 {
		return "", errors.New("response has no www-authenticate header")
	}

	// check if the platform is supported
	expectedSecretFilePath := getAzureArcPlatformPath(platform)
	if expectedSecretFilePath == "" {
		return "", errors.New("platform not supported, expected linux or windows")
	}

	parts := strings.Split(wwwAuthenticateHeader, "Basic realm=")
	if len(parts) < 2 {
		return "", fmt.Errorf("basic realm= not found in the string, instead found: %s", wwwAuthenticateHeader)
	}

	secretFilePath := parts

	// check that the file in the file path is a .key file
	fileName := filepath.Base(secretFilePath[1])
	if !strings.HasSuffix(fileName, azureArcFileExtension) {
		return "", fmt.Errorf("invalid file extension, expected %s, got %s", azureArcFileExtension, filepath.Ext(fileName))
	}

	// check that file path from header matches the expected file path for the platform
	if expectedSecretFilePath != filepath.Dir(secretFilePath[1]) {
		return "", fmt.Errorf("invalid file path, expected %s, got %s", expectedSecretFilePath, filepath.Dir(secretFilePath[1]))
	}

	fileInfo, err := os.Stat(secretFilePath[1])
	if err != nil {
		return "", fmt.Errorf("failed to get metadata for %s due to error: %s", secretFilePath[1], err)
	}

	// Throw an error if the secret file's size is greater than 4096 bytes
	if s := fileInfo.Size(); s > azureArcMaxFileSizeBytes {
		return "", fmt.Errorf("invalid secret file size, expected %d, file size was %d", azureArcMaxFileSizeBytes, s)
	}

	// Attempt to read the contents of the secret file
	secret, err := os.ReadFile(secretFilePath[1])
	if err != nil {
		return "", fmt.Errorf("failed to read %q due to error: %s", secretFilePath[1], err)
	}

	return string(secret), nil
}
