// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/*
Package ops provides operations to various backend services using REST clients.

The REST type provides several clients that can be used to communicate to backends.
Usage is simple:
	rest := ops.New()

	// Creates an authority client and calls the GetUserRealm() method.
	userRealm, err := rest.Authority().GetUserRealm(ctx, authParameters)
	if err != nil {
		// Do something
	}
*/
package ops

import (
	"net/http"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/apps/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/apps/internal/requests/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/apps/internal/requests/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/apps/internal/requests/ops/internal/comm"
	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/apps/internal/requests/ops/wstrust"
)

// TODO(jdoak): After integration, remove:
// 	msalbase.CreateUserRealm()
//  requests.CreateTenantDiscoveryResponse()

// REST provides REST clients for communicating with various backends used by MSAL.
type REST struct {
	client *comm.Client
}

// New is the constructor for REST.
func New() *REST {
	return &REST{client: comm.New(&http.Client{})}
}

// Authority returns a client for querying information about various authorities.
func (r *REST) Authority() authority.Client {
	return authority.Client{Comm: r.client}
}

// AccessTokens returns a client that can be used to get various access tokens for
// authorization purposes.
func (r *REST) AccessTokens() accesstokens.Client {
	return accesstokens.Client{Comm: r.client, TokenRespFunc: msalbase.CreateTokenResponse2}
}

// WSTrust provides access to various metadata in a WSTrust service. This data can
// be used to gain tokens based on SAML data using the client provided by AccessTokens().
func (r *REST) WSTrust() wstrust.Client {
	return wstrust.Client{Comm: r.client}
}
