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
	"sync"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
	// "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	// "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
	// "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

const (
	// DefaultToIMDS indicates that the source is defaulted to IMDS since no environment variables are set.
	DefaultToIMDS = 0

	// AzureArc represents the source to acquire token for managed identity is Azure Arc.
	AzureArc = 1
)

// Client is a client that provides access to Managed Identity token calls.
type Client struct {
	// AuthParams      authority.AuthParams // DO NOT EVER MAKE THIS A POINTER! See "Note" in New(). also may remove from here
	cacheAccessorMu *sync.RWMutex
	httpClient      ops.HTTPClient
	MiType          ID
	// Token    			*oauth.Client
	// pmanager manager 	// todo :  expose the manager from base.
	// cacheAccessor   		cache.ExportReplace
}

// clientOptions are optional settings for New(). These options are set using various functions
// returning Option calls.
type clientOptions struct {
	claims     string // bypasses cache, does nothing else
	httpClient ops.HTTPClient
	// disableInstanceDiscovery bool // always false
	// clientId     string
}

// type withClaimsOption struct{ Claims string }
type withHTTPClientOption struct {
	HttpClient ops.HTTPClient
}

// Option is an optional argument to New().
type Option interface{ apply(*clientOptions) }
type ClientOption interface{ ClientOption() }
type AcquireTokenOptions struct {
	Claims string
}
type AcquireTokenOption interface{ apply(*AcquireTokenOptions) }

// Source represents the managed identity sources supported.
type Source int

type systemAssignedValue string

type ID interface {
	value() string
}

func SystemAssigned() ID {
	return systemAssignedValue("")
}

type ClientID string
type ObjectID string
type ResourceID string

func (s systemAssignedValue) value() string { return string(s) }
func (c ClientID) value() string            { return string(c) }
func (o ObjectID) value() string            { return string(o) }
func (r ResourceID) value() string          { return string(r) }

func (w AcquireTokenOptions) AcquireTokenOption()  {}
func (w withHTTPClientOption) AcquireTokenOption() {}
func (w Client) apply(opts *clientOptions)         { opts.httpClient = w.HttpClient }

// WithClaims sets additional claims to request for the token, such as those required by conditional access policies.
// Use this option when Azure AD returned a claims challenge for a prior request. The argument must be decoded.
func WithClaims(claims string) AcquireTokenOptions {
	return AcquireTokenOptions{Claims: claims}
}

// WithHTTPClient allows for a custom HTTP client to be set.
func WithHTTPClient(httpClient ops.HTTPClient) Option {
	return withHTTPClientOption{HttpClient: httpClient}
}

// Client to be used to acquire tokens for managed identity.
// ID: [SystemAssigned()], [ClientID("clientID")], [ResourceID("resourceID")], [ObjectID("objectID")]
//
// Options: [WithHTTPClient]
func New(id ID, options ...Option) (Client, error) {
	fmt.Println("idType: ", id.value())

	opts := clientOptions{ // work on this side where
		httpClient: shared.DefaultClient,
	}

	for _, option := range options {
		option.apply(&opts)
	}

	client := Client{ // TODO :: check for http client
		MiType: id,
	}

	return client, nil
}

type responseJson struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    string `json:"expires_in"`
	ExpiresOn    string `json:"expires_on"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

// Acquires tokens from the configured managed identity on an azure resource.
//
// Resource: scopes application is requesting access to
// Options: [WithClaims]
func (client Client) AcquireToken(context context.Context, resource string, options ...AcquireTokenOption) (base.AuthResult, error) {
	o := AcquireTokenOptions{}

	for _, option := range options {
		option.apply(&o)
	}

	if client.MiType == SystemAssigned() {
		systemUrl := "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"
		var msiEndpoint *url.URL
		msi_endpoint, err := url.Parse(systemUrl)
		if err != nil {
			fmt.Println("Error creating URL: ", err)
			return base.AuthResult{}, nil
		}
		msiParameters := msi_endpoint.Query()
		msiParameters.Add("resource", "https://management.azure.com/")
		msiEndpoint.RawQuery = msiParameters.Encode()
		req, err := http.NewRequest(http.MethodGet, msiEndpoint.String(), nil)
		if err != nil {
			fmt.Println("Error creating HTTP request: ", err)
			return base.AuthResult{}, nil
		}
		req.Header.Add("Metadata", "true")

		resp, err := client.httpClient.Do(req)
		if err != nil {
			fmt.Println("Error calling token endpoint: ", err)
			return base.AuthResult{}, nil
		}

		// Pull out response body
		responseBytes, err := io.ReadAll(resp.Body)
		defer resp.Body.Close()
		if err != nil {
			fmt.Println("Error reading response body : ", err)
			return base.AuthResult{}, nil
		}

		// Unmarshall response body into struct
		var r accesstokens.TokenResponse
		err = json.Unmarshal(responseBytes, &r)
		if err != nil {
			fmt.Println("Error unmarshalling the response:", err)
			return base.AuthResult{}, nil
		}

		println("Access token :: ", r.AccessToken)
		return base.NewAuthResult(r, shared.Account{})
	}

	// all the other options.
	return base.AuthResult{}, nil
}

// Detects and returns the managed identity source available on the environment.
func GetSource() Source {
	return DefaultToIMDS
}
