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

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
)

// General request querry parameter names
const (
	MetaHTTPHeadderName               = "Metadata"
	APIVersionQuerryParameterName     = "api-version"
	ResourceBodyOrQuerryParameterName = "resource"
)

// UAMI querry parameter name
const (
	MIQuerryParameterClientId   = "client_id"
	MIQuerryParameterObjectId   = "object_id"
	MIQuerryParameterResourceId = "mi_res_id"
)

// Appservice
// end point comes from enviournment variable ??
const (
	AppServiceMSIEndPointAPIVersion = "2019-08-01"
)

// Arc
const (
	ARCAPIEndpoint = "http://127.0.0.1:40342/metadata/identity/oauth2/token"
	ARCAPIVersion  = "2019-11-01"
)

// IMDS
const (
	IMDSEndpoint   = "http://169.254.169.254/metadata/identity/oauth2/token"
	IMDSAPIVersion = "2018-02-01"
)

const (
	// DefaultToIMDS indicates that the source is defaulted to IMDS since no environment variables are set.
	DefaultToIMDS = 0

	// AzureArc represents the source to acquire token for managed identity is Azure Arc.
	AzureArc = 1
)

// id type managed identity
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

// Client is a client that provides access to Managed Identity token calls.
type Client struct {
	// cacheAccessorMu *sync.RWMutex
	httpClient ops.HTTPClient
	MiType     ID
	// pmanager manager 	// todo :  expose the manager from base.
	// cacheAccessor   		cache.ExportReplace
}

type ClientOptions struct {
	httpClient ops.HTTPClient
}

type AcquireTokenOptions struct {
	Claims string
}

type ClientOption func(o *ClientOptions)

type AcquireTokenOption func(o *AcquireTokenOptions)

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
	fmt.Println("idType: ", id.value())

	opts := ClientOptions{ // work on this side where
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

// Acquires tokens from the configured managed identity on an azure resource.
//
// Resource: scopes application is requesting access to
// Options: [WithClaims]
func (client Client) AcquireToken(context context.Context, resource string, options ...AcquireTokenOption) (base.AuthResult, error) {
	o := AcquireTokenOptions{}

	for _, option := range options {
		option(&o)
	}

	// try and find some resource which can be accessed
	// service fabric  GET
	// app service  GET
	// could shell  POST request
	// azure arc  GET
	// default :: IMDS  GET
	//
	// Sources that send GET requests: App Service, Azure Arc, IMDS, Service Fabric
	//
	// Sources that send POST requests: Cloud Shell

	var msiEndpoint *url.URL
	msiEndpoint, err := url.Parse(IMDSEndpoint)
	if err != nil {
		fmt.Println("Error creating URL: ", err)
		return base.AuthResult{}, nil
	}
	msiParameters := msiEndpoint.Query()
	msiParameters.Add("api-version", "2018-02-01")
	msiParameters.Add("resource", resource)

	if len(o.Claims) > 0 {
		msiParameters.Add("claims", o.Claims)
	}

	switch client.MiType.(type) {
	case ClientID:
		msiParameters.Add(MIQuerryParameterClientId, client.MiType.value())
	case ResourceID:
		msiParameters.Add(MIQuerryParameterResourceId, client.MiType.value())
	case ObjectID:
		msiParameters.Add(MIQuerryParameterObjectId, client.MiType.value())
	case systemAssignedValue: // not adding anything
	default:
		return base.AuthResult{}, fmt.Errorf("Type not suported")

	}

	msiEndpoint.RawQuery = msiParameters.Encode()
	token, err := getTokenForURL(msiEndpoint, client.httpClient)
	if err != nil {
		return base.AuthResult{}, fmt.Errorf("URL not formed")
	}
	println("Access token **  ", token.AccessToken)
	return base.NewAuthResult(token, shared.Account{})
}

// Detects and returns the managed identity source available on the environment.
func GetSource() Source {
	return DefaultToIMDS
}
