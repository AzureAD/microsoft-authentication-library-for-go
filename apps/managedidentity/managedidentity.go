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
	"io/ioutil"
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
	linuxSupportedPath             = "/var/opt/azcmagent/tokens/"
	linuxAzureArcFilePath          = "/opt/azcmagent/bin/himds"
	windowsTokenPath               = "\\AzureConnectedMachineAgent\\Tokens\\"
	WindowsHimdsPath               = "\\AzureConnectedMachineAgent\\himds.exe"

	// Environment Variables
	IdentityEndpointEnvVar              = "IDENTITY_ENDPOINT"
	IdentityHeaderEnvVar                = "IDENTITY_HEADER"
	AzurePodIdentityAuthorityHostEnvVar = "AZURE_POD_IDENTITY_AUTHORITY_HOST"
	ArcIMDSEnvVar                       = "IMDS_ENDPOINT"
	MsiEndpointEnvVar                   = "MSI_ENDPOINT"
	IdentityServerThumbprintEnvVar      = "IDENTITY_SERVER_THUMBPRINT"

	//Errors
	getSourceError = "API doesn't support specifying a user-assigned managed identity at runtime"
)

var supportedAzureArcPlatforms = map[string]string{
	"windows": fmt.Sprintf("%s\\AzureConnectedMachineAgent\\Tokens\\", os.Getenv("ProgramData")),
	"linux":   "/var/opt/azcmagent/tokens/",
}

var azureArcFileDetection = map[string]string{
	"windows": fmt.Sprintf("%s\\AzureConnectedMachineAgent\\himds.exe", os.Getenv("ProgramFiles")),
	"linux":   "/opt/azcmagent/bin/himds",
}

// arcKeyDirectory returns the directory expected to contain Azure Arc keys
var arcKeyDirectory = func() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return linuxSupportedPath, nil
	case "windows":
		pd := os.Getenv("ProgramData")
		if pd == "" {
			return "", errors.New("environment variable ProgramData has no value")
		}
		return filepath.Join(pd, windowsTokenPath), nil
	default:
		return "", fmt.Errorf("unsupported OS %q", runtime.GOOS)
	}
}

type responseHandler func(*http.Response, context.Context, string) (accesstokens.TokenResponse, error)

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
	println("GetSource: 1")
	if _, ok := os.LookupEnv(IdentityEndpointEnvVar); ok {
		println("GetSource: 2")
		if _, ok := os.LookupEnv(IdentityHeaderEnvVar); ok {
			println("GetSource: 3")
			if _, ok := os.LookupEnv(IdentityServerThumbprintEnvVar); ok {
				println("GetSource: 4")
				if id != nil {
					println("GetSource: 5")
					return DefaultToIMDS, fmt.Errorf("%s %s", ServiceFabric, getSourceError)
				}
				println("GetSource: 6")
				return ServiceFabric, nil
			} else {
				println("GetSource: 7")
				return AppService, nil
			}
		} else if _, ok := os.LookupEnv(ArcIMDSEnvVar); ok {
			println("GetSource: 8")
			if _, ok := id.(systemAssignedValue); !ok {
				println("GetSource: 9")
				return DefaultToIMDS, fmt.Errorf("%s %s", AzureArc, getSourceError)
			}
			println("GetSource: 10")
			return AzureArc, nil
		}
	} else if _, ok := os.LookupEnv(MsiEndpointEnvVar); ok {
		println("GetSource: 11")
		return CloudShell, nil
	}
	println("GetSource: 12")
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
		req, err = createAzureArcAuthRequest(ctx, client.miType, resource, o.claims)
		if err != nil {
			return base.AuthResult{}, err
		}

		// need to perform preliminary request to retrieve the secret key challenge provided by the HIMDS service
		// this is done when we get a 401 response, which will be handled by the response handler
		tokenResponse, err = client.getTokenForRequest(ctx, req, client.handleAzureArcResponse)
		if err != nil {
			return base.AuthResult{}, err
		}
	default:
		req, err = createIMDSAuthRequest(ctx, client.miType, resource, o.claims)
		if err != nil {
			return base.AuthResult{}, err
		}

		tokenResponse, err = client.getTokenForRequest(ctx, req, nil)
		if err != nil {
			return base.AuthResult{}, err
		}

	}

	return base.NewAuthResult(tokenResponse, shared.Account{})

}

func createIMDSAuthRequest(ctx context.Context, id ID, resource string, claims string) (*http.Request, error) {
	var msiEndpoint *url.URL
	msiEndpoint, err := url.Parse(imdsEndpoint)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse %q: %s", imdsEndpoint, err)
	}
	msiParameters := msiEndpoint.Query()
	msiParameters.Set(apiVersionQueryParameterName, imdsAPIVersion)
	resource = strings.TrimSuffix(resource, "/.default")
	msiParameters.Set(resourceQueryParameterName, resource)

	if len(claims) > 0 {
		msiParameters.Set("claims", claims)
	}

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

func createAzureArcAuthRequest(ctx context.Context, id ID, resource string, claims string) (*http.Request, error) {
	var msiEndpoint *url.URL
	var err error

	envEndpoint, ok := os.LookupEnv(IdentityEndpointEnvVar)
	if !ok {
		msiEndpoint, err = url.Parse(azureArcEndpoint)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse %q: %s", envEndpoint, err)
		}
	} else {
		msiEndpoint, err = url.Parse(envEndpoint)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse %q: %s", envEndpoint, err)
		}
	}

	msiParameters := msiEndpoint.Query()
	msiParameters.Set(apiVersionQueryParameterName, azureArcAPIVersion)
	resource = strings.TrimSuffix(resource, "/.default")
	msiParameters.Set(resourceQueryParameterName, resource)

	if len(claims) > 0 {
		msiParameters.Set("claims", claims)
	}

	if _, ok := id.(systemAssignedValue); !ok {
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

func (client Client) getTokenForRequest(ctx context.Context, req *http.Request, resHandler responseHandler) (accesstokens.TokenResponse, error) {
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
	case http.StatusUnauthorized:

		if resHandler != nil {
			return resHandler(resp, ctx, r.Claims)
		}
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

func (c *Client) handleAzureArcResponse(response *http.Response, ctx context.Context, claims string) (accesstokens.TokenResponse, error) {
	if response.StatusCode == http.StatusUnauthorized {
		wwwAuthenticateHeader := response.Header.Get(wwwAuthenticateHeaderName)
		platform := runtime.GOOS

		if len(wwwAuthenticateHeader) == 0 {
			return accesstokens.TokenResponse{}, fmt.Errorf("response has no www-authenticate header")
		}

		// the WWW-Authenticate header is expected in the following format: Basic realm=/some/file/path.key
		// _, p, found := strings.Cut(wwwAuthenticateHeader, "=")
		// if !found {
		// 	return accesstokens.TokenResponse{}, fmt.Errorf("unexpected WWW-Authenticate header from HIMDS: %s", wwwAuthenticateHeader)
		// }
		if !strings.Contains(wwwAuthenticateHeader, "Basic realm=") {
			return accesstokens.TokenResponse{}, fmt.Errorf("www-authenticate header is in an unsupported format")
		}

		var secretFilePath string

		// split the header to get the secret file path
		parts := strings.Split(wwwAuthenticateHeader, "Basic realm=")
		if len(parts) > 1 {
			secretFilePath = parts[1]
		} else {
			return accesstokens.TokenResponse{}, fmt.Errorf("Basic realm= not found in the string")
		}

		// check if the platform is supported
		if _, ok := supportedAzureArcPlatforms[platform]; !ok {
			return accesstokens.TokenResponse{}, fmt.Errorf("platform not supported")
		}

		// get the expected Windows or Linux file path
		expectedSecretFilePath, ok := supportedAzureArcPlatforms[platform]
		if !ok {
			return accesstokens.TokenResponse{}, fmt.Errorf("error getting expected secret file path")
		}

		// check that the file in the file path is a .key file
		fileName := filepath.Base(secretFilePath)
		if !strings.HasSuffix(fileName, azureArcFileExtension) {
			return accesstokens.TokenResponse{}, fmt.Errorf("invalid file extension")
		}

		// check that file path from header matches the expected file path for the platform
		if expectedSecretFilePath+fileName != secretFilePath {
			return accesstokens.TokenResponse{}, fmt.Errorf("invalid file path")
		}

		// Attempt to get the secret file's size, in bytes,
		fileInfo, err := os.Stat(secretFilePath)
		if err != nil {
			return accesstokens.TokenResponse{}, fmt.Errorf("unable to read secret file")
		}

		secretFileSize := fileInfo.Size()

		// Throw an error if the secret file's size is greater than 4096 bytes
		if secretFileSize > azureArcMaxFileSizeBytes {
			return accesstokens.TokenResponse{}, fmt.Errorf("invalid secret")
		}

		// Attempt to read the contents of the secret file
		secret, err := ioutil.ReadFile(secretFilePath)
		if err != nil {
			return accesstokens.TokenResponse{}, fmt.Errorf("unable to read the secret file")
		}

		authHeaderValue := fmt.Sprintf("Basic %s", string(secret))

		println("Adding auth header to the request")

		req, err := createAzureArcAuthRequest(ctx, SystemAssigned(), "https://management.azure.com/", claims)
		if err != nil {
			return accesstokens.TokenResponse{}, fmt.Errorf("error creating http request %s", err)
		}

		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", string(authHeaderValue)))

		return c.getTokenForRequest(ctx, req, nil)
		// expected, err := arcKeyDirectory()
		// if err != nil {
		// 	return accesstokens.TokenResponse{}, err
		// }

		// if filepath.Dir(p) != expected || !strings.HasSuffix(p, azureArcFileExtension) {
		// 	return accesstokens.TokenResponse{}, fmt.Errorf("unexpected file path from HIMDS service: %s", p)
		// }

		// f, err := os.Stat(p)
		// if err != nil {
		// 	return accesstokens.TokenResponse{}, fmt.Errorf("could not stat: %s %s", p, err)
		// }

		// if s := f.Size(); s > azureArcMaxFileSizeBytes {
		// 	return accesstokens.TokenResponse{}, fmt.Errorf("key is too large (%d bytes)", s)
		// }

		// key, err := os.ReadFile(p)
		// if err != nil {
		// 	return accesstokens.TokenResponse{}, fmt.Errorf("could not read %s: %s", p, err)
		// }
	}

	return accesstokens.TokenResponse{}, fmt.Errorf("managed identity error: %s", response.Status)
}
