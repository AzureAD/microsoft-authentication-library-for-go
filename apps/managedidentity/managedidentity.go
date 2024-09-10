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
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
)

// General request querry parameter names
const (
	metaHTTPHeadderName           = "Metadata"
	apiVersionQuerryParameterName = "api-version"
	resourceQuerryParameterName   = "resource"
)

// UAMI querry parameter name
const (
	miQuerryParameterClientId   = "client_id"
	miQuerryParameterObjectId   = "object_id"
	miQuerryParameterResourceId = "msi_res_id"
)

// IMDS
const (
	imdsEndpoint   = "http://169.254.169.254/metadata/identity/oauth2/token"
	imdsAPIVersion = "2018-02-01"
)

const (
	// DefaultToIMDS indicates that the source is defaulted to IMDS since no environment variables are set.
	defaultToIMDS = 0

	// AzureArc represents the source to acquire token for managed identity is Azure Arc.
	azureArc = 1
)

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

type Client struct {
	httpClient ops.HTTPClient
	miType     ID
}

type ClientOptions struct {
	httpClient ops.HTTPClient
}

type AcquireTokenOptions struct {
	claims string
}

type ClientOption func(o *ClientOptions)

type AcquireTokenOption func(o *AcquireTokenOptions)

// WithClaims sets additional claims to request for the token, such as those required by conditional access policies.
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

	client := Client{
		miType:     id,
		httpClient: opts.httpClient,
	}

	return client, nil
}

func createIMDSAuthRequest(_ context.Context, id ID, resource string, claims string) (*http.Request, error) {
	var msiEndpoint *url.URL
	msiEndpoint, err := url.Parse(imdsEndpoint)
	if err != nil {
		return &http.Request{}, fmt.Errorf("Error creating URL as parsing the URL filed")
	}

	msiParameters := msiEndpoint.Query()
	msiParameters.Add(apiVersionQuerryParameterName, "2018-02-01")

	resource = removeSuffix(resource, "/.default")
	print(resource)
	msiParameters.Add(resourceQuerryParameterName, resource)

	if len(claims) > 0 {
		msiParameters.Add("claims", claims)
	}

	switch t := id.(type) {
	case ClientID:
		if len(string(t)) > 0 {
			msiParameters.Add(miQuerryParameterClientId, string(t))
		} else {
			return &http.Request{}, fmt.Errorf("ClientId parameter is empty for %T", t)
		}
	case ResourceID:
		if len(string(t)) > 0 {
			msiParameters.Add(miQuerryParameterResourceId, string(t))
		} else {
			return &http.Request{}, fmt.Errorf("ResourceID parameter is empty for %T", t)
		}
	case ObjectID:
		if len(string(t)) > 0 {
			msiParameters.Add(miQuerryParameterObjectId, string(t))
		} else {
			return &http.Request{}, fmt.Errorf("ObjectID parameter is empty for %T", t)
		}
	case systemAssignedValue: // not adding anything
	default:
		return &http.Request{}, fmt.Errorf("unsupported type %T", id)
	}

	msiEndpoint.RawQuery = msiParameters.Encode()
	fmt.Println(msiEndpoint)
	req, err := http.NewRequest(http.MethodGet, msiEndpoint.String(), nil)
	if err != nil {
		return &http.Request{}, fmt.Errorf("Error creating request")
	}
	return req, nil
}

func getTokenForRequest(_ context.Context, req *http.Request, httpClient ops.HTTPClient) (accesstokens.TokenResponse, error) {
	req.Header.Add(metaHTTPHeadderName, "true")

	resp, err := httpClient.Do(req)
	if err != nil {
		return accesstokens.TokenResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return accesstokens.TokenResponse{}, fmt.Errorf("Error code was non Ok %T ", resp.StatusCode)
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

// RemoveSuffix removes the specified 'suffix' from 'str' if it exists.
func removeSuffix(str, suffix string) string {
	if strings.HasSuffix(str, suffix) {
		return str[:len(str)-len(suffix)] // Remove the suffix if it exists
	}
	return str // Return the original string if suffix doesn't exist
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
	req, err := createIMDSAuthRequest(ctx, client.miType, resource, o.claims)
	if err != nil {
		fmt.Println("Error creating URL: ", err)
		return base.AuthResult{}, fmt.Errorf("Error while creating request")
	}
	tokenResponse, err := getTokenForRequest(ctx, req, client.httpClient)
	if err != nil {
		return base.AuthResult{}, err
	}
	return base.NewAuthResult(tokenResponse, shared.Account{})
}
