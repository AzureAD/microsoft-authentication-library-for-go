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
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
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
	imdsEndpoint   = "http://169.254.169.254/metadata/identity/oauth2/token"
	imdsAPIVersion = "2018-02-01"

	// Azure Arc
	azureArcEndpoint               = "http://127.0.0.1:40342/metadata/identity/oauth2/token"
	azureArcAPIVersion             = "2020-06-01"
	azureArcFileExtension          = ".key"
	azureArcMaxFileSizeBytes int64 = 4096
	linuxTokenPath                 = "/var/opt/azcmagent/tokens/"
	linuxHimdsPath                 = "/opt/azcmagent/bin/himds"
	windowsTokenPath               = "\\AzureConnectedMachineAgent\\Tokens\\"
	windowsHimdsPath               = "\\AzureConnectedMachineAgent\\himds.exe"

	// Environment Variables
	identityEndpointEnvVar              = "IDENTITY_ENDPOINT"
	identityHeaderEnvVar                = "IDENTITY_HEADER"
	azurePodIdentityAuthorityHostEnvVar = "AZURE_POD_IDENTITY_AUTHORITY_HOST"
	arcIMDSEnvVar                       = "IMDS_ENDPOINT"
	msiEndpointEnvVar                   = "MSI_ENDPOINT"
	identityServerThumbprintEnvVar      = "IDENTITY_SERVER_THUMBPRINT"
)

var getAzureArcPlatformPath = func() string {
	switch runtime.GOOS {
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			return ""
		}
		return fmt.Sprintf("%s%s", programData, windowsTokenPath)
	case "linux":
		return linuxTokenPath
	default:
		return ""
	}
}

var getAzureArcFilePath = func() string {
	switch runtime.GOOS {
	case "windows":
		programFiles := os.Getenv("ProgramFiles")
		if programFiles == "" {
			return ""
		}
		return fmt.Sprintf("%s%s", programFiles, windowsHimdsPath)
	case "linux":
		return linuxHimdsPath
	default:
		return ""
	}
}

// var supportedAzureArcPlatforms = map[string]string{
// 	"windows": fmt.Sprintf("%s%s", os.Getenv("ProgramData"), windowsTokenPath),
// 	"linux":   linuxTokenPath,
// }

// var azureArcOsToFileMap = map[string]string{
// 	"windows": fmt.Sprintf("%s%s", os.Getenv("ProgramFiles"), windowsHimdsPath),
// 	"linux":   linuxHimdsPath,
// }

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
	return systemAssignedValue("")
}

type Client struct {
	httpClient ops.HTTPClient
	miType     ID
	source     Source
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

	return client, nil
}

// Detects and returns the managed identity source available on the environment.
func GetSource(id ID) (Source, error) {
	identityEndpoint := os.Getenv(identityEndpointEnvVar)
	identityHeader := os.Getenv(identityHeaderEnvVar)
	identityServerThumbprint := os.Getenv(identityServerThumbprintEnvVar)
	msiEndpoint := os.Getenv(msiEndpointEnvVar)

	if identityEndpoint != "" && identityHeader != "" {
		if identityServerThumbprint != "" {
			return ServiceFabric, nil
		}
		return AppService, nil
	} else if msiEndpoint != "" {
		return CloudShell, nil
	} else if validateAzureArcEnvironment(identityEndpoint, imdsEndpoint, runtime.GOOS) {
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
	var req *http.Request
	var err error

	for _, option := range options {
		option(&o)
	}
	var tokenResponse accesstokens.TokenResponse
	switch client.source {
	case AzureArc:
		req, err = createAzureArcAuthRequest(ctx, client.miType, resource)
		if err != nil {
			return base.AuthResult{}, err
		}

		// need to perform preliminary request to retrieve the secret key challenge provided by the HIMDS service
		// this is done when we get a 401 response, which will be handled by the response handler
		tokenResponse, err = client.getTokenForRequest(ctx, req)
		if err != nil {
			switch callErr := err.(type) {
			case errors.CallErr:
				switch callErr.Resp.StatusCode {
				case http.StatusUnauthorized:
					response, err := client.handleAzureArcResponse(ctx, callErr.Resp, resource)
					if err != nil {
						return base.AuthResult{}, err
					}

					return base.NewAuthResult(response, shared.Account{})
				}
			}
			return base.AuthResult{}, err
		}
	case DefaultToIMDS:
		req, err = createIMDSAuthRequest(ctx, client.miType, resource)
		if err != nil {
			return base.AuthResult{}, err
		}

		tokenResponse, err = client.getTokenForRequest(ctx, req)
		if err != nil {
			return base.AuthResult{}, err
		}
	default:
		return base.AuthResult{}, fmt.Errorf("unsupported source %q", client.source)
	}

	return base.NewAuthResult(tokenResponse, shared.Account{})

}

func (client Client) getTokenForRequest(ctx context.Context, req *http.Request) (accesstokens.TokenResponse, error) {
	var r accesstokens.TokenResponse

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return accesstokens.TokenResponse{}, err
	}

	responseBytes, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()

	if err != nil {
		return accesstokens.TokenResponse{}, err
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted:
	default:
		sd := strings.TrimSpace(string(responseBytes))
		if sd != "" {
			return accesstokens.TokenResponse{}, errors.CallErr{
				Req:  req,
				Resp: resp,
				Err: fmt.Errorf("http call(%s)(%s) error: reply status code was %d:\n%s",
					req.URL.String(),
					req.Method,
					resp.StatusCode,
					sd),
			}
		}
		return accesstokens.TokenResponse{}, errors.CallErr{
			Req:  req,
			Resp: resp,
			Err:  fmt.Errorf("http call(%s)(%s) error: reply status code was %d", req.URL.String(), req.Method, resp.StatusCode),
		}
	}

	err = json.Unmarshal(responseBytes, &r)
	return r, err
}

func fileExists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func createIMDSAuthRequest(ctx context.Context, id ID, resource string) (*http.Request, error) {
	var msiEndpoint *url.URL
	msiEndpoint, err := url.Parse(imdsEndpoint)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse %q: %s", imdsEndpoint, err)
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

func createAzureArcAuthRequest(ctx context.Context, id ID, resource string) (*http.Request, error) {
	identityEndpoint := azureArcEndpoint
	var msiEndpoint *url.URL

	if _, ok := id.(systemAssignedValue); !ok {
		return nil, errors.New("Azure Arc doesn't support user assigned managed identities")
	}

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

func validateAzureArcEnvironment(identityEndpoint, imdsEndpoint string, platform string) bool {
	if identityEndpoint != "" && imdsEndpoint != "" {
		return true
	}

	himdsFilePath := getAzureArcFilePath()

	if himdsFilePath != "" && fileExists(himdsFilePath) {
		return true
	}

	return false
}

func (c *Client) handleAzureArcResponse(ctx context.Context, response *http.Response, resource string) (accesstokens.TokenResponse, error) {
	if response.StatusCode == http.StatusUnauthorized {
		wwwAuthenticateHeader := response.Header.Get(wwwAuthenticateHeaderName)

		if len(wwwAuthenticateHeader) == 0 {
			return accesstokens.TokenResponse{}, errors.New("response has no www-authenticate header")
		}

		// check if the platform is supported
		expectedSecretFilePath := getAzureArcPlatformPath()
		if expectedSecretFilePath == "" {
			return accesstokens.TokenResponse{}, errors.New("platform not supported")
		}

		secret, err := handleSecretFile(wwwAuthenticateHeader, expectedSecretFilePath)
		if err != nil {
			return accesstokens.TokenResponse{}, err
		}

		authHeaderValue := fmt.Sprintf("Basic %s", string(secret))

		req, err := createAzureArcAuthRequest(ctx, SystemAssigned(), resource)
		if err != nil {
			return accesstokens.TokenResponse{}, err
		}

		req.Header.Set("Authorization", authHeaderValue)

		return c.getTokenForRequest(ctx, req)
	}

	return accesstokens.TokenResponse{}, fmt.Errorf("managed identity error: %d", response.StatusCode)
}

func handleSecretFile(wwwAuthenticateHeader, expectedSecretFilePath string) ([]byte, error) {
	var secretFilePath string

	// split the header to get the secret file path
	parts := strings.Split(wwwAuthenticateHeader, "Basic realm=")
	if len(parts) > 1 {
		secretFilePath = parts[1]
	} else {
		return nil, fmt.Errorf("basic realm= not found in the string, instead found: %s", wwwAuthenticateHeader)
	}

	// check that the file in the file path is a .key file
	fileName := filepath.Base(secretFilePath)

	if !strings.HasSuffix(fileName, azureArcFileExtension) {
		return nil, fmt.Errorf("invalid file extension, expected %s, got %s", azureArcFileExtension, filepath.Ext(fileName))
	}

	// check that file path from header matches the expected file path for the platform
	if strings.TrimSpace(filepath.Join(expectedSecretFilePath, fileName)) != secretFilePath {
		return nil, fmt.Errorf("invalid file path, expected %s, got %s", secretFilePath, filepath.Join(expectedSecretFilePath, fileName))
	}

	fileInfo, err := os.Stat(secretFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to get file info for path %s", secretFilePath)
	}

	secretFileSize := fileInfo.Size()

	// Throw an error if the secret file's size is greater than 4096 bytes
	if secretFileSize > azureArcMaxFileSizeBytes {
		return nil, fmt.Errorf("invalid secret file size, expected %d, file size was %d", azureArcMaxFileSizeBytes, secretFileSize)
	}

	// Attempt to read the contents of the secret file
	secret, err := os.ReadFile(secretFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to read the secret file at path %s", secretFilePath)
	}

	return secret, nil
}
