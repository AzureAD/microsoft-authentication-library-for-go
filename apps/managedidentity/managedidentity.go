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

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
)

const (
	// Sources
	// DefaultToIMDS indicates that the source is defaulted to IMDS since no environment variables are set.
	// AzureArc represents the source to acquire token for managed identity is Azure Arc.
	DefaultToIMDS Source = 0
	AzureArc      Source = 1
	ServiceFabric Source = 2
	CloudShell    Source = 3
	AppService    Source = 4

	// Request Parameters
	MetaHTTPHeaderName               = "Metadata"
	APIVersionQueryParameterName     = "api-version"
	ResourceBodyOrQueryParameterName = "resource"

	// Query Parameters
	MIQueryParameterClientId   = "client_id"
	MIQueryParameterObjectId   = "object_id"
	MIQueryParameterResourceId = "mi_res_id"

	// Endpoints
	ArcAPIEndpoint = "http://127.0.0.1:40342/metadata/identity/oauth2/token"
	IMDSEndpoint   = "http://169.254.169.254" + IMDSTokenPath

	// Endpoint Versions
	AppServiceMSIEndPointVersion = "2019-08-01"
	ArcAPIVersion                = "2019-11-01"
	IMDSAPIVersion               = "2018-02-01"

	// Token Path
	IMDSTokenPath = "/metadata/identity/oauth2/token"

	// Environment Variables
	IdentityEndpointEnvVar              = "IDENTITY_ENDPOINT"
	IdentityHeaderEnvVar                = "IDENTITY_HEADER"
	AzurePodIdentityAuthorityHostEnvVar = "AZURE_POD_IDENTITY_AUTHORITY_HOST"
	IMDSEnvVar                          = "IMDS_ENDPOINT"
	MsiEndpointEnvVar                   = "MSI_ENDPOINT"
	IdentityServerThumbprintEnvVar      = "IDENTITY_SERVER_THUMBPRINT"
)

// Client is a client that provides access to Managed Identity token calls.
type Client struct {
	// cacheAccessorMu *sync.RWMutex
	httpClient ops.HTTPClient
	MiType     ID
	// pmanager manager 	// todo :  expose the manager from base.
	// cacheAccessor   		cache.ExportReplace
}

// ClientOptions are optional settings for New(). These options are set using various functions
// returning Option calls.
type ClientOptions struct {
	httpClient ops.HTTPClient
}

type AcquireTokenOptions struct {
	Claims string
}

type ClientOption func(o *ClientOptions)
type AcquireTokenOption func(o *AcquireTokenOptions)

// Source represents the managed identity sources supported.
type Source int

type ID interface {
	value() string
}

type systemAssignedValue string // its private for a reason to make the input consistent.
type ClientID string
type ObjectID string
type ResourceID string

func (s systemAssignedValue) value() string { return string(s) }
func (c ClientID) value() string            { return string(c) }
func (o ObjectID) value() string            { return string(o) }
func (r ResourceID) value() string          { return string(r) }
func SystemAssigned() ID {
	return systemAssignedValue("")
}

func (s Source) String() string {
	switch s {
	case DefaultToIMDS:
		return "DefaultToIMDS"
	case AzureArc:
		return "AzureArc"
	case ServiceFabric:
		return "ServiceFabric"
	case CloudShell:
		return "CloudShell"
	case AppService:
		return "AppService"
	default:
		return fmt.Sprintf("UnknownSource(%d)", s)
	}
}

// WithClaims sets additional claims to request for the token, such as those required by conditional access policies.
// Use this option when Azure AD returned a claims challenge for a prior request. The argument must be decoded.
func WithClaims(claims string) AcquireTokenOption {
	return func(o *AcquireTokenOptions) {
		o.Claims = claims
	}
}

// WithHTTPClient allows for a custom HTTP client to be set.
func WithHTTPClient(httpClient ops.HTTPClient) ClientOption {
	return func(o *ClientOptions) {
		o.httpClient = httpClient
	}
}

// Client to be used to acquire tokens for managed identity.
// ID: [SystemAssigned()], [ClientID("clientID")], [ResourceID("resourceID")], [ObjectID("objectID")]
//
// Options: [WithHTTPClient]
func New(id ID, options ...ClientOption) (Client, error) {
	opts := ClientOptions{
		httpClient: shared.DefaultClient,
	}

	for _, option := range options {
		option(&opts)
	}

	client := Client{ // TODO :: check for http client
		MiType:     id,
		httpClient: opts.httpClient,
	}

	return client, nil
}

// Acquires tokens from the configured managed identity on an azure resource.
//
// Resource: scopes application is requesting access to
// Options: [WithClaims]
func (client Client) AcquireToken(context context.Context, resource string, options ...AcquireTokenOption) (base.AuthResult, error) {
	o := AcquireTokenOptions{}

	for _, option := range options {
		option(&o)
	}

	if client.MiType == SystemAssigned() {
		var msiEndpoint *url.URL
		msiEndpoint, err := url.Parse(IMDSEndpoint)
		if err != nil {
			fmt.Println("Error creating URL: ", err)
			return base.AuthResult{}, nil
		}
		msiParameters := msiEndpoint.Query()
		msiParameters.Add("api-version", "2018-02-01")
		msiParameters.Add("resource", resource)
		msiEndpoint.RawQuery = msiParameters.Encode()

		token, err := getTokenForURL(msiEndpoint, client.httpClient)

		println("Access token :: ", token.AccessToken)
		return base.NewAuthResult(token, shared.Account{})
	}

	return base.AuthResult{}, nil
}

// Detects and returns the managed identity source available on the environment.
func GetSource(client Client) Source {
	if _, ok := os.LookupEnv(IdentityEndpointEnvVar); ok {
		if _, ok := os.LookupEnv(IdentityHeaderEnvVar); ok {
			if _, ok := os.LookupEnv(IdentityServerThumbprintEnvVar); ok {
				return ServiceFabric
			} else {
				return AppService
			}
		} else if _, ok := os.LookupEnv(IMDSEnvVar); ok {
			return AzureArc
		}
	} else if _, ok := os.LookupEnv(MsiEndpointEnvVar); ok {
		return CloudShell
	}

	return DefaultToIMDS
}

func getTokenForURL(url *url.URL, httpClient ops.HTTPClient) (accesstokens.TokenResponse, error) {
	req, err := http.NewRequest(http.MethodGet, url.String(), nil)
	if err != nil {
		return accesstokens.TokenResponse{}, err
	}
	req.Header.Add("Metadata", "true")

	resp, err := httpClient.Do(req)
	if err != nil {
		return accesstokens.TokenResponse{}, err
	}

	// Pull out response body
	responseBytes, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return accesstokens.TokenResponse{}, err
	}

	// Unmarshall response body into struct
	var r accesstokens.TokenResponse
	err = json.Unmarshal(responseBytes, &r)
	if err != nil {
		return accesstokens.TokenResponse{}, err
	}
	return r, nil
}
