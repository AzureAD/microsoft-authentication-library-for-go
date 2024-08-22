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
	"fmt"
	"sync"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

const (
	// DefaultToIMDS indicates that the source is defaulted to IMDS since no environment variables are set.
	DefaultToIMDS = 0

	// AzureArc represents the source to acquire token for managed identity is Azure Arc.
	AzureArc = 1
)

// Client is a client that provides access to Managed Identity token calls.
type Client struct {
	AuthParams      authority.AuthParams // DO NOT EVER MAKE THIS A POINTER! See "Note" in New(). also may remove from here
	cacheAccessorMu *sync.RWMutex
	// base                ops.HTTPClient
	// managedIdentityType Type
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

type withClaimsOption struct{ Claims string }
type withHTTPClientOption struct{ HttpClient ops.HTTPClient }

// Option is an optional argument to New().
type Option interface{ apply(*clientOptions) }
type ClientOption interface{ ClientOption() }
type AcquireTokenOption interface{ AcquireTokenOption() }

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

func (w withClaimsOption) AcquireTokenOption()           {}
func (w withHTTPClientOption) AcquireTokenOption()       {}
func (w withHTTPClientOption) apply(opts *clientOptions) { opts.httpClient = w.HttpClient }

// WithClaims sets additional claims to request for the token, such as those required by conditional access policies.
// Use this option when Azure AD returned a claims challenge for a prior request. The argument must be decoded.
func WithClaims(claims string) AcquireTokenOption {
	return withClaimsOption{Claims: claims}
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

	opts := clientOptions{
		claims: "claims",
	}

	for _, option := range options {
		option.apply(&opts)
	}

	authInfo, err := authority.NewInfoFromAuthorityURI("authorityURI", true, false)
	if err != nil {
		return Client{}, err
	}

	authParams := authority.NewAuthParams(id.value(), authInfo)
	client := Client{ // Note: Hey, don't even THINK about making Base into *Base. See "design notes" in public.go and confidential.go
		AuthParams:      authParams,
		cacheAccessorMu: &sync.RWMutex{},
		// manager:         storage.New(token),
		// pmanager:        storage.NewPartitionedManager(token),
	}

	return client, err
}

// Acquires tokens from the configured managed identity on an azure resource.
//
// Resource: scopes application is requesting access to
// Options: [WithClaims]
func (client Client) AcquireToken(context context.Context, resource string, options ...AcquireTokenOption) (base.AuthResult, error) {
	return base.AuthResult{}, nil
}

// Detects and returns the managed identity source available on the environment.
func GetSource() Source {
	return DefaultToIMDS
}
