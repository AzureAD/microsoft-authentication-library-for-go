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
	"sync/atomic"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/storage"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/version"
	"github.com/google/uuid"
)

// AuthResult contains the results of one token acquisition operation.
// For details see https://aka.ms/msal-net-authenticationresult
type AuthResult = base.AuthResult

type TokenSource = base.TokenSource

const (
	TokenSourceIdentityProvider = base.TokenSourceIdentityProvider
	TokenSourceCache            = base.TokenSourceCache
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
	linuxTokenPath                 = "/var/opt/azcmagent/tokens" // #nosec G101
	linuxHimdsPath                 = "/opt/azcmagent/bin/himds"
	azureConnectedMachine          = "AzureConnectedMachineAgent"
	himdsExecutableName            = "himds.exe"
	tokenName                      = "Tokens"

	// App Service
	appServiceAPIVersion = "2019-08-01"

	// AzureML
	azureMLAPIVersion = "2017-09-01"
	// Service Fabric
	serviceFabricAPIVersion = "2019-07-01-preview"

	// Environment Variables
	identityEndpointEnvVar              = "IDENTITY_ENDPOINT"
	identityHeaderEnvVar                = "IDENTITY_HEADER"
	azurePodIdentityAuthorityHostEnvVar = "AZURE_POD_IDENTITY_AUTHORITY_HOST"
	imdsEndVar                          = "IMDS_ENDPOINT"
	msiEndpointEnvVar                   = "MSI_ENDPOINT"
	msiSecretEnvVar                     = "MSI_SECRET"
	identityServerThumbprintEnvVar      = "IDENTITY_SERVER_THUMBPRINT"

	defaultRetryCount = 3

	// clientClaimsCacheKey is the CacheKeyComponents key used to partition the token cache by
	// client-originated claims (see WithClaimsFromClient). The component value is the raw claims string.
	clientClaimsCacheKey = "client_claims"

	// xmsAzNwperimid is the only custom claim MSIv1 (IMDS v1) accepts (see WithClaimsFromClient).
	xmsAzNwperimid = "xms_az_nwperimid"
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
	canRefresh         *atomic.Value
}

type AcquireTokenOptions struct {
	claims       string
	clientClaims string
}

type ClientOption func(*Client)

type AcquireTokenOption func(o *AcquireTokenOptions)

// WithClaims sets additional claims to request for the token, such as those required by token revocation or conditional access policies.
// Use this option when Azure AD returned a claims challenge for a prior request. The argument must be decoded.
func WithClaims(claims string) AcquireTokenOption {
	return func(o *AcquireTokenOptions) {
		o.claims = claims
	}
}

// WithClaimsFromClient forwards client-originated claims (for example an NSP "xms_az_nwperimid"
// claim) to the managed identity endpoint.
//
// Unlike [WithClaims] (server-issued claims challenges, which bypass the token cache), tokens acquired
// with client claims ARE cached and the cache entry is keyed on the claims value, so different claims
// values produce separate cache entries. Pass a stable, non-dynamic value and the same string on each
// call (the raw string is used verbatim as part of the cache key; MSAL does not normalize it).
//
// Client claims are only supported for the IMDS managed identity source; using this option with any
// other source results in an error at token-acquisition time. For IMDS (MSIv1) the only permitted
// top-level claim is "xms_az_nwperimid"; any other key results in an error before the network call.
// An empty or whitespace-only value is ignored. The argument must be a JSON object.
func WithClaimsFromClient(claims string) AcquireTokenOption {
	return func(o *AcquireTokenOptions) {
		if strings.TrimSpace(claims) == "" {
			// Ignore empty/whitespace claims so callers can pass a value unconditionally.
			return
		}
		o.clientClaims = claims
	}
}

// WithHTTPClient allows for a custom HTTP client to be set.
func WithHTTPClient(httpClient ops.HTTPClient) ClientOption {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

func WithRetryPolicyDisabled() ClientOption {
	return func(c *Client) {
		c.retryPolicyEnabled = false
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
	zero := atomic.Value{}
	zero.Store(false)
	client := Client{
		miType:             id,
		httpClient:         shared.DefaultClient,
		retryPolicyEnabled: true,
		source:             source,
		canRefresh:         &zero,
	}
	for _, option := range options {
		option(&client)
	}
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

// This function wraps time.Now() and is used for refreshing the application
// was created to test the function against refreshin
var now = time.Now

// Acquires tokens from the configured managed identity on an azure resource.
//
// Resource: scopes application is requesting access to
// Options: [WithClaims], [WithClaimsFromClient]
func (c Client) AcquireToken(ctx context.Context, resource string, options ...AcquireTokenOption) (AuthResult, error) {
	resource = strings.TrimSuffix(resource, "/.default")
	o := AcquireTokenOptions{}
	for _, option := range options {
		option(&o)
	}
	c.authParams.Scopes = []string{resource}

	// Client-originated claims participate in the cache (unlike server-issued WithClaims, which
	// bypasses it). Partition the cache entry on the raw claims value so different claims values
	// map to different tokens. The value is forwarded to IMDS later in the request pipeline.
	c.authParams.ClientClaims = o.clientClaims
	if o.clientClaims != "" {
		if c.authParams.CacheKeyComponents == nil {
			c.authParams.CacheKeyComponents = make(map[string]string)
		}
		c.authParams.CacheKeyComponents[clientClaimsCacheKey] = o.clientClaims
	}

	// ignore cached access tokens when given claims
	if o.claims == "" {
		stResp, err := cacheManager.Read(ctx, c.authParams)
		if err != nil {
			return AuthResult{}, err
		}
		ar, err := base.AuthResultFromStorage(stResp)
		if err == nil {
			if !stResp.AccessToken.RefreshOn.T.IsZero() && !stResp.AccessToken.RefreshOn.T.After(now()) && c.canRefresh.CompareAndSwap(false, true) {
				defer c.canRefresh.Store(false)
				if tr, er := c.getToken(ctx, resource); er == nil {
					return tr, nil
				}
			}
			ar.AccessToken, err = c.authParams.AuthnScheme.FormatAccessToken(ar.AccessToken)
			return ar, err
		}
	}
	return c.getToken(ctx, resource)
}

func (c Client) getToken(ctx context.Context, resource string) (AuthResult, error) {
	// Client claims are only forwarded to the IMDS source. Reject other sources before issuing a
	// request rather than silently dropping the claims and polluting the cache with a key the
	// endpoint never saw.
	if c.authParams.ClientClaims != "" && c.source != DefaultToIMDS {
		return AuthResult{}, fmt.Errorf("WithClaimsFromClient is only supported for IMDS-based managed identity sources; the detected source is %q", c.source)
	}
	switch c.source {
	case AzureArc:
		return c.acquireTokenForAzureArc(ctx, resource)
	case AzureML:
		return c.acquireTokenForAzureML(ctx, resource)
	case CloudShell:
		return c.acquireTokenForCloudShell(ctx, resource)
	case DefaultToIMDS:
		return c.acquireTokenForIMDS(ctx, resource)
	case AppService:
		return c.acquireTokenForAppService(ctx, resource)
	case ServiceFabric:
		return c.acquireTokenForServiceFabric(ctx, resource)
	default:
		return AuthResult{}, fmt.Errorf("unsupported source %q", c.source)
	}
}

func (c Client) acquireTokenForAppService(ctx context.Context, resource string) (AuthResult, error) {
	req, err := createAppServiceAuthRequest(ctx, c.miType, resource)
	if err != nil {
		return AuthResult{}, err
	}
	tokenResponse, err := c.getTokenForRequest(req, resource)
	if err != nil {
		return AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

func (c Client) acquireTokenForIMDS(ctx context.Context, resource string) (AuthResult, error) {
	req, err := createIMDSAuthRequest(ctx, c.miType, resource, c.authParams.ClientClaims)
	if err != nil {
		return AuthResult{}, err
	}
	tokenResponse, err := c.getTokenForRequest(req, resource)
	if err != nil {
		return AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

func (c Client) acquireTokenForCloudShell(ctx context.Context, resource string) (AuthResult, error) {
	req, err := createCloudShellAuthRequest(ctx, resource)
	if err != nil {
		return AuthResult{}, err
	}
	tokenResponse, err := c.getTokenForRequest(req, resource)
	if err != nil {
		return AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

func (c Client) acquireTokenForAzureML(ctx context.Context, resource string) (AuthResult, error) {
	req, err := createAzureMLAuthRequest(ctx, c.miType, resource)
	if err != nil {
		return AuthResult{}, err
	}
	tokenResponse, err := c.getTokenForRequest(req, resource)
	if err != nil {
		return AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

func (c Client) acquireTokenForServiceFabric(ctx context.Context, resource string) (AuthResult, error) {
	req, err := createServiceFabricAuthRequest(ctx, resource)
	if err != nil {
		return AuthResult{}, err
	}
	tokenResponse, err := c.getTokenForRequest(req, resource)
	if err != nil {
		return AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

func (c Client) acquireTokenForAzureArc(ctx context.Context, resource string) (AuthResult, error) {
	req, err := createAzureArcAuthRequest(ctx, resource, "")
	if err != nil {
		return AuthResult{}, err
	}

	response, err := c.httpClient.Do(req)
	if err != nil {
		return AuthResult{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusUnauthorized {
		return AuthResult{}, fmt.Errorf("expected a 401 response, received %d", response.StatusCode)
	}

	secret, err := c.getAzureArcSecretKey(response, runtime.GOOS)
	if err != nil {
		return AuthResult{}, err
	}

	secondRequest, err := createAzureArcAuthRequest(ctx, resource, string(secret))
	if err != nil {
		return AuthResult{}, err
	}

	tokenResponse, err := c.getTokenForRequest(secondRequest, resource)
	if err != nil {
		return AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

func authResultFromToken(authParams authority.AuthParams, token accesstokens.TokenResponse) (AuthResult, error) {
	if cacheManager == nil {
		return AuthResult{}, errors.New("cache instance is nil")
	}
	account, err := cacheManager.Write(authParams, token)
	if err != nil {
		return AuthResult{}, err
	}
	// if refreshOn is not set, set it to half of the time until expiry if expiry is more than 2 hours away
	if token.RefreshOn.T.IsZero() {
		if lifetime := time.Until(token.ExpiresOn); lifetime > 2*time.Hour {
			token.RefreshOn.T = time.Now().Add(lifetime / 2)
		}
	}
	ar, err := base.NewAuthResult(token, account)
	if err != nil {
		return AuthResult{}, err
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
		defer tryCancel()
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
	if err != nil {
		return r, errors.InvalidJsonErr{
			Err: fmt.Errorf("error parsing the json error: %s", err),
		}
	}
	r.GrantedScopes.Slice = append(r.GrantedScopes.Slice, resource)

	return r, err
}

// validateMSIv1Claims enforces the MSIv1 (IMDS v1) allowlist: the only permitted top-level claim is
// xms_az_nwperimid. Any other key would cause IMDS to return HTTP 400 with no useful diagnostic, so
// reject it early with a clear error. The claims JSON must be a JSON object.
func validateMSIv1Claims(claimsJSON string) error {
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal([]byte(claimsJSON), &parsed); err != nil {
		return fmt.Errorf("WithClaimsFromClient: claims must be a JSON object: %w", err)
	}
	if parsed == nil {
		return errors.New("WithClaimsFromClient: claims must be a JSON object")
	}
	for k := range parsed {
		if k != xmsAzNwperimid {
			return fmt.Errorf("MSIv1 (IMDS v1) only supports the %q custom claim, but the claims JSON contained the unsupported key %q; remove all keys other than %q when using WithClaimsFromClient", xmsAzNwperimid, k, xmsAzNwperimid)
		}
	}
	return nil
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

func createIMDSAuthRequest(ctx context.Context, id ID, resource string, clientClaims string) (*http.Request, error) {
	msiEndpoint, err := url.Parse(imdsDefaultEndpoint)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse %q: %s", imdsDefaultEndpoint, err)
	}
	msiParameters := msiEndpoint.Query()
	msiParameters.Set(apiVersionQueryParameterName, imdsAPIVersion)
	msiParameters.Set(resourceQueryParameterName, resource)

	if clientClaims != "" {
		// MSIv1 (IMDS v1) only accepts the xms_az_nwperimid claim; reject anything else early so
		// the caller gets a clear error instead of an opaque HTTP 400 from IMDS.
		if err := validateMSIv1Claims(clientClaims); err != nil {
			return nil, err
		}
		// Set the raw claims JSON; url.Values.Encode below URL-encodes the value.
		msiParameters.Set("claims", clientClaims)
	}

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
	req.Header.Set("x-client-SKU", version.SKU)
	req.Header.Set("x-client-Ver", version.Version)
	req.Header.Set("x-ms-client-request-id", uuid.New().String())
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
