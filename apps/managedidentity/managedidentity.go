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
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/storage"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/logger"
)

const (
	// DefaultToIMDS indicates that the source is defaulted to IMDS when no environment variables are set.
	DefaultToIMDS Source = "DefaultToIMDS"
	AzureArc      Source = "AzureArc"
	ServiceFabric Source = "ServiceFabric"
	CloudShell    Source = "CloudShell"
	AppService    Source = "AppService"

	// General request query parameter names
	metaHTTPHeaderName           = "Metadata"
	apiVersionQueryParameterName = "api-version"
	resourceQueryParameterName   = "resource"
	wwwAuthenticateHeaderName    = "www-authenticate"

	// UAMI query parameter name
	miQueryParameterClientId   = "client_id"
	miQueryParameterObjectId   = "object_id"
	miQueryParameterResourceId = "msi_res_id"

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
	logger             *logger.Logger
}

type ClientOptions struct {
	httpClient         ops.HTTPClient
	retryPolicyEnabled bool
	logger             *logger.Logger
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

// WithLogger allows for a logger to be set.
func WithLogger(logger *logger.Logger) ClientOption {
	return func(o *ClientOptions) {
		o.logger = logger
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
// Options: [WithHTTPClient]
func New(id ID, options ...ClientOption) (Client, error) {
	source, err := GetSource()
	if err != nil {
		return Client{}, err
	}

	// If source is Azure Arc return an error, as Azure Arc allow accepts System Assigned managed identities.
	if source == AzureArc {
		switch id.(type) {
		case UserAssignedClientID, UserAssignedResourceID, UserAssignedObjectID:
			return Client{}, errors.New("azure Arc doesn't support user assigned managed identities")
		}
	}
	opts := ClientOptions{
		httpClient:         shared.DefaultClient,
		retryPolicyEnabled: true,
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
	}
	client.log(logger.Info, fmt.Sprintf("Managed Identity will use %s", source))
	fakeAuthInfo, err := authority.NewInfoFromAuthorityURI("https://login.microsoftonline.com/managed_identity", false, true)
	if err != nil {
		return Client{}, err
	}
	client.authParams = authority.NewAuthParams(client.miType.value(), fakeAuthInfo)
	return client, nil
}

func (c Client) log(level logger.Level, message string, fields ...any) {
	if c.logger != nil {
		c.logger.Log(level, message, fields)
	}
}

// GetSource detects and returns the managed identity source available on the environment.
func GetSource() (Source, error) {
	identityEndpoint := os.Getenv(identityEndpointEnvVar)
	identityHeader := os.Getenv(identityHeaderEnvVar)
	identityServerThumbprint := os.Getenv(identityServerThumbprintEnvVar)
	msiEndpoint := os.Getenv(msiEndpointEnvVar)
	imdsEndpoint := os.Getenv(imdsEndVar)

	if identityEndpoint != "" && identityHeader != "" {
		if identityServerThumbprint != "" {
			return ServiceFabric, nil
		}
		return AppService, nil
	} else if msiEndpoint != "" {
		return CloudShell, nil
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
	c.log(logger.Info, fmt.Sprintf("ManagedIdentity AcquireToken for resouce %s", resource))
	resource = strings.TrimSuffix(resource, "/.default")
	o := AcquireTokenOptions{}
	for _, option := range options {
		option(&o)
	}
	c.authParams.Scopes = []string{resource}

	// ignore cached access tokens when given claims
	if o.claims == "" {
		storageTokenResponse, err := cacheManager.Read(ctx, c.authParams)
		if err != nil {
			return base.AuthResult{}, err
		}
		ar, err := base.AuthResultFromStorage(storageTokenResponse)
		if err == nil {
			c.log(logger.Info, "ManagedIdentity AcquireToken from cache")
			ar.AccessToken, err = c.authParams.AuthnScheme.FormatAccessToken(ar.AccessToken)
			return ar, err
		}
	}
	c.log(logger.Info, fmt.Sprintf("ManagedIdentity AcquireToken to server for resource %s", resource))
	switch c.source {
	case AzureArc:
		return acquireTokenForAzureArc(ctx, c, resource)
	case DefaultToIMDS:
		return acquireTokenForIMDS(ctx, c, resource)
	case AppService:
		return acquireTokenForAppService(ctx, c, resource)
	default:
		return base.AuthResult{}, fmt.Errorf("unsupported source %q", c.source)
	}
}

func acquireTokenForAppService(ctx context.Context, c Client, resource string) (base.AuthResult, error) {
	req, err := createAppServiceAuthRequest(ctx, c.miType, resource, c)
	if err != nil {
		c.log(logger.Err, fmt.Sprintf("Error while creasting request for app service : %s", err))
		return base.AuthResult{}, err
	}
	tokenResponse, err := c.getTokenForRequest(req)
	if err != nil {
		c.log(logger.Err, fmt.Sprintf("Error for acquire token for app service : %s", err))
		return base.AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

func acquireTokenForIMDS(ctx context.Context, c Client, resource string) (base.AuthResult, error) {
	req, err := createIMDSAuthRequest(ctx, c.miType, resource, c)
	if err != nil {
		c.log(logger.Err, fmt.Sprintf("Error while creasting request for IMDS : %s", err))
		return base.AuthResult{}, err
	}
	tokenResponse, err := c.getTokenForRequest(req)
	if err != nil {
		c.log(logger.Err, fmt.Sprintf("Error for acquire token for IMDS : %s", err))
		return base.AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

func acquireTokenForAzureArc(ctx context.Context, client Client, resource string) (base.AuthResult, error) {
	req, err := createAzureArcAuthRequest(ctx, resource, "")
	if err != nil {
		client.log(logger.Err, fmt.Sprintf("Error while creasting request for azure arc : %s", err))
		return base.AuthResult{}, err
	}

	response, err := client.httpClient.Do(req)
	if err != nil {
		client.log(logger.Err, fmt.Sprintf("Error for azure arc auth request : %s", err))
		return base.AuthResult{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusUnauthorized {
		return base.AuthResult{}, fmt.Errorf("expected a 401 response, received %d", response.StatusCode)
	}

	secret, err := client.getAzureArcSecretKey(response, runtime.GOOS)
	if err != nil {
		return base.AuthResult{}, err
	}

	secondRequest, err := createAzureArcAuthRequest(ctx, resource, string(secret))
	if err != nil {
		client.log(logger.Err, fmt.Sprintf("Error while creating request for azure arc : %s", err))
		return base.AuthResult{}, err
	}

	tokenResponse, err := client.getTokenForRequest(secondRequest)
	if err != nil {
		client.log(logger.Err, fmt.Sprintf("Error for acquire token for azure arc : %s", err))
		return base.AuthResult{}, err
	}
	return authResultFromToken(client.authParams, tokenResponse)
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
		tryCtx, tryCancel := context.WithTimeout(req.Context(), time.Second*15)
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		cloneReq := req.Clone(tryCtx)
		resp, err = c.httpClient.Do(cloneReq)
		retrylist := retryStatusCodes
		if c.source == DefaultToIMDS {
			retrylist = retryCodesForIMDS
		}
		if err == nil && !contains(retrylist, resp.StatusCode) {
			tryCancel()
			return resp, nil
		}
		select {
		case <-time.After(time.Second):
		case <-req.Context().Done():
			err = req.Context().Err()
			tryCancel()
			return resp, err
		}
		tryCancel()
	}
	return resp, err
}

func (c Client) getTokenForRequest(req *http.Request) (accesstokens.TokenResponse, error) {
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
	r.GrantedScopes.Slice = append(r.GrantedScopes.Slice, req.URL.Query().Get(resourceQueryParameterName))
	return r, err
}

func createAppServiceAuthRequest(ctx context.Context, id ID, resource string, c Client) (*http.Request, error) {
	identityEndpoint := os.Getenv(identityEndpointEnvVar)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, identityEndpoint, nil)
	if err != nil {
		return nil, err
	}
	c.log(logger.Debug, fmt.Sprintf("Creating azure arc managed identity source Endpoint URI: %s", identityEndpoint))
	req.Header.Set("X-IDENTITY-HEADER", os.Getenv(identityHeaderEnvVar))
	q := req.URL.Query()
	q.Set("api-version", appServiceAPIVersion)
	q.Set("resource", resource)
	switch t := id.(type) {
	case UserAssignedClientID:
		c.log(logger.Debug, "Adding user assigned object id to the request.")
		q.Set(miQueryParameterClientId, string(t))
	case UserAssignedResourceID:
		c.log(logger.Debug, "Adding user assigned object id to the request.")
		q.Set(miQueryParameterResourceId, string(t))
	case UserAssignedObjectID:
		c.log(logger.Debug, "Adding user assigned object id to the request.")
		q.Set(miQueryParameterObjectId, string(t))
	case systemAssignedValue:
	default:
		return nil, fmt.Errorf("unsupported type %T", id)
	}
	c.log(logger.Debug, fmt.Sprintf("IMDS managed identity source. Endpoint URI: %s", identityEndpoint))
	req.URL.RawQuery = q.Encode()
	return req, nil
}

func createIMDSAuthRequest(ctx context.Context, id ID, resource string, c Client) (*http.Request, error) {
	msiEndpoint, err := url.Parse(imdsDefaultEndpoint)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse %q: %s", imdsDefaultEndpoint, err)
	}
	c.log(logger.Debug, fmt.Sprintf("Creating IMDS managed identity source. Endpoint URI: %s", msiEndpoint))
	msiParameters := msiEndpoint.Query()
	msiParameters.Set(apiVersionQueryParameterName, imdsAPIVersion)
	msiParameters.Set(resourceQueryParameterName, resource)

	switch t := id.(type) {
	case UserAssignedClientID:
		c.log(logger.Debug, "Adding user assigned client id to the request.")
		msiParameters.Set(miQueryParameterClientId, string(t))
	case UserAssignedResourceID:
		c.log(logger.Debug, "Adding user assigned resource id to the request.")
		msiParameters.Set(miQueryParameterResourceId, string(t))
	case UserAssignedObjectID:
		c.log(logger.Debug, "Adding user assigned object id to the request.")
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
	c.log(logger.Debug, fmt.Sprintf("IMDS managed identity source. Endpoint URI: %s", msiEndpoint))
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
