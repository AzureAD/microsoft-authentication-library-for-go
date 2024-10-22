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

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/storage"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
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
	azureConnectedMachine          = "AzureConnectedMachine"
	himdsExecutableName            = "himds.exe"
	tokenName                      = "Tokens"

	// Environment Variables
	identityEndpointEnvVar              = "IDENTITY_ENDPOINT"
	identityHeaderEnvVar                = "IDENTITY_HEADER"
	azurePodIdentityAuthorityHostEnvVar = "AZURE_POD_IDENTITY_AUTHORITY_HOST"
	imdsEndVar                          = "IMDS_ENDPOINT"
	msiEndpointEnvVar                   = "MSI_ENDPOINT"
	identityServerThumbprintEnvVar      = "IDENTITY_SERVER_THUMBPRINT"
)

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

var getAzureArcFilePath = func(platform string) string {
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
	httpClient ops.HTTPClient
	miType     ID
	source     Source
	authParams authority.AuthParams
}

type ClientOptions struct {
	httpClient ops.HTTPClient
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

// Client to be used to acquire tokens for managed identity.
// ID: [SystemAssigned], [UserAssignedClientID], [UserAssignedResourceID], [UserAssignedObjectID]
//
// Options: [WithHTTPClient]
func New(id ID, options ...ClientOption) (Client, error) {
	source, err := GetSource(id)
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
		httpClient: shared.DefaultClient,
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
		miType:     id,
		httpClient: opts.httpClient,
		source:     source,
	}

	client.authParams, err = createFakeAuthParams(client)
	if err != nil {
		return Client{}, err
	}

	return client, nil
}

// GetSource detects and returns the managed identity source available on the environment.
func GetSource(id ID) (Source, error) {
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
	} else if isAzureArcEnvironment(identityEndpoint, imdsEndpoint, runtime.GOOS) {
		return AzureArc, nil
	}

	return DefaultToIMDS, nil
}

// Acquires tokens from the configured managed identity on an azure resource.
//
// Resource: scopes application is requesting access to
// Options: [WithClaims]
func (client Client) AcquireToken(ctx context.Context, resource string, options ...AcquireTokenOption) (base.AuthResult, error) {
	o := AcquireTokenOptions{}
	for _, option := range options {
		option(&o)
	}

	// ignore cached access tokens when given claims
	if o.claims == "" {
		if cacheManager == nil {
			return base.AuthResult{}, errors.New("cache instance is nil")
		}
		storageTokenResponse, err := cacheManager.Read(ctx, client.authParams)
		if err != nil {
			return base.AuthResult{}, err
		}
		ar, err := base.AuthResultFromStorage(storageTokenResponse)
		if err == nil {
			ar.AccessToken, err = client.authParams.AuthnScheme.FormatAccessToken(ar.AccessToken)
			return ar, err
		}
	}

	switch client.source {
	case AzureArc:
		return acquireAzureArc(ctx, client, resource, client.authParams)
	case DefaultToIMDS:
		return acquireIMDS(ctx, client, resource, client.authParams)
	default:
		return base.AuthResult{}, fmt.Errorf("unsupported source %q", client.source)
	}
}

func acquireIMDS(ctx context.Context, client Client, resource string, fakeAuthParams authority.AuthParams) (base.AuthResult, error) {
	req, err := createIMDSAuthRequest(ctx, client.miType, resource)
	if err != nil {
		return base.AuthResult{}, err
	}

	tokenResponse, err := client.getTokenForRequest(req)
	if err != nil {
		return base.AuthResult{}, err
	}
	return authResultFromToken(fakeAuthParams, tokenResponse)
}

func acquireAzureArc(ctx context.Context, client Client, resource string, fakeAuthParams authority.AuthParams) (base.AuthResult, error) {
	req, err := createAzureArcAuthRequest(ctx, resource)
	if err != nil {
		return base.AuthResult{}, err
	}

	tokenResponse, err := client.getTokenForRequest(req)
	if err != nil {
		return handleAzureArcExpectedError(ctx, client, resource, fakeAuthParams, err)
	}

	return authResultFromToken(fakeAuthParams, tokenResponse)
}

func handleAzureArcExpectedError(ctx context.Context, client Client, resource string, fakeAuthParams authority.AuthParams, err error) (base.AuthResult, error) {
	var newCallErr errors.CallErr

	if errors.As(err, &newCallErr) {
		response, err := client.handleAzureArcResponse(ctx, newCallErr.Resp, resource, runtime.GOOS)
		if err != nil {
			return base.AuthResult{}, err
		}

		return authResultFromToken(fakeAuthParams, response)
	}

	return base.AuthResult{}, err
}

func createFakeAuthParams(client Client) (authority.AuthParams, error) {
	fakeAuthInfo, err := authority.NewInfoFromAuthorityURI("https://login.microsoftonline.com/managed_identity", false, true)
	if err != nil {
		return authority.AuthParams{}, err
	}

	return authority.NewAuthParams(client.miType.value(), fakeAuthInfo), nil
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

func (client Client) getTokenForRequest(req *http.Request) (accesstokens.TokenResponse, error) {
	var r accesstokens.TokenResponse

	resp, err := client.httpClient.Do(req)
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

func createIMDSAuthRequest(ctx context.Context, id ID, resource string) (*http.Request, error) {
	msiEndpoint, err := url.Parse(imdsDefaultEndpoint)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse %q: %s", imdsDefaultEndpoint, err)
	}
	msiParameters := msiEndpoint.Query()
	msiParameters.Set(apiVersionQueryParameterName, imdsAPIVersion)
	resource = strings.TrimSuffix(resource, "/.default")
	msiParameters.Set(resourceQueryParameterName, resource)

	switch t := id.(type) {
	case UserAssignedClientID:
		msiParameters.Set(miQueryParameterClientId, string(t))
	case UserAssignedResourceID:
		msiParameters.Set(miQueryParameterResourceId, string(t))
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

func createAzureArcAuthRequest(ctx context.Context, resource string) (*http.Request, error) {
	identityEndpoint := azureArcEndpoint
	msiEndpoint, parseErr := url.Parse(identityEndpoint)

	if parseErr != nil {
		return nil, fmt.Errorf("couldn't parse %q: %s", identityEndpoint, parseErr)
	}

	msiParameters := msiEndpoint.Query()
	msiParameters.Set(apiVersionQueryParameterName, azureArcAPIVersion)
	resource = strings.TrimSuffix(resource, "/.default")
	msiParameters.Set(resourceQueryParameterName, resource)

	msiEndpoint.RawQuery = msiParameters.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, msiEndpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating http request %s", err)
	}
	req.Header.Set(metaHTTPHeaderName, "true")
	return req, nil
}

func isAzureArcEnvironment(identityEndpoint, imdsEndpoint string, platform string) bool {
	if identityEndpoint != "" && imdsEndpoint != "" {
		return true
	}

	himdsFilePath := getAzureArcFilePath(platform)

	if himdsFilePath != "" {
		if _, err := os.Stat(himdsFilePath); err == nil {
			return true
		}
	}

	return false
}

func (c *Client) handleAzureArcResponse(ctx context.Context, response *http.Response, resource string, platform string) (accesstokens.TokenResponse, error) {
	if response.StatusCode == http.StatusUnauthorized {
		wwwAuthenticateHeader := response.Header.Get(wwwAuthenticateHeaderName)

		if len(wwwAuthenticateHeader) == 0 {
			return accesstokens.TokenResponse{}, errors.New("response has no www-authenticate header")
		}

		// check if the platform is supported
		expectedSecretFilePath := getAzureArcPlatformPath(platform)
		if expectedSecretFilePath == "" {
			return accesstokens.TokenResponse{}, fmt.Errorf("platform not supported, expected linux or windows, got %s", platform)
		}

		secret, err := handleSecretFile(wwwAuthenticateHeader, expectedSecretFilePath)
		if err != nil {
			return accesstokens.TokenResponse{}, err
		}

		authHeaderValue := fmt.Sprintf("Basic %s", string(secret))

		req, err := createAzureArcAuthRequest(ctx, resource)
		if err != nil {
			return accesstokens.TokenResponse{}, err
		}

		req.Header.Set("Authorization", authHeaderValue)

		return c.getTokenForRequest(req)
	}

	return accesstokens.TokenResponse{}, fmt.Errorf("managed identity error: %d", response.StatusCode)
}

func handleSecretFile(wwwAuthenticateHeader, expectedSecretFilePath string) ([]byte, error) {
	// split the header to get the secret file path
	parts := strings.Split(wwwAuthenticateHeader, "Basic realm=")
	if len(parts) < 2 {
		return nil, fmt.Errorf("basic realm= not found in the string, instead found: %s", wwwAuthenticateHeader)
	}

	secretFilePath := parts

	// check that the file in the file path is a .key file
	fileName := filepath.Base(secretFilePath[1])
	if !strings.HasSuffix(fileName, azureArcFileExtension) {
		return nil, fmt.Errorf("invalid file extension, expected %s, got %s", azureArcFileExtension, filepath.Ext(fileName))
	}

	// check that file path from header matches the expected file path for the platform
	if expectedSecretFilePath != filepath.Dir(secretFilePath[1]) {
		return nil, fmt.Errorf("invalid file path, expected %s, got %s", expectedSecretFilePath, filepath.Dir(secretFilePath[1]))
	}

	fileInfo, err := os.Stat(secretFilePath[1])
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata for %s due to error: %s", secretFilePath[1], err)
	}

	secretFileSize := fileInfo.Size()

	// Throw an error if the secret file's size is greater than 4096 bytes
	if s := fileInfo.Size(); s > azureArcMaxFileSizeBytes {
		return nil, fmt.Errorf("invalid secret file size, expected %d, file size was %d", azureArcMaxFileSizeBytes, secretFileSize)
	}

	// Attempt to read the contents of the secret file
	secret, err := os.ReadFile(secretFilePath[1])
	if err != nil {
		return nil, fmt.Errorf("failed to read %q due to error: %s", secretFilePath[1], err)
	}

	return secret, nil
}
