// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"context"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

//ClientCredentialRequest stores the values required to acquire a token from the authority using a client credentials grant
type ClientCredentialRequest struct {
	webRequestManager WebRequestManager
	authParameters    msalbase.AuthParametersInternal
	clientCredential  msalbase.ClientCredential
}

//CreateClientCredentialRequest creates an instance of ClientCredentialRequest
func CreateClientCredentialRequest(wrm WebRequestManager, authParams msalbase.AuthParametersInternal, clientCred msalbase.ClientCredential) *ClientCredentialRequest {
	return &ClientCredentialRequest{wrm, authParams, clientCred}
}

//Execute performs the token acquisition request and returns a token response or an error
func (req *ClientCredentialRequest) Execute(ctx context.Context) (msalbase.TokenResponse, error) {
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(ctx, req.authParameters.AuthorityInfo, "")
	if err != nil {
		return msalbase.TokenResponse{}, err
	}
	req.authParameters.Endpoints = endpoints

	if req.clientCredential.GetCredentialType() == msalbase.ClientCredentialSecret {
		return req.webRequestManager.GetAccessTokenWithClientSecret(ctx, req.authParameters, req.clientCredential.GetSecret())
	}
	jwt, err := req.clientCredential.GetAssertion().GetJWT(req.authParameters)
	if err != nil {
		return msalbase.TokenResponse{}, err
	}
	return req.webRequestManager.GetAccessTokenWithAssertion(ctx, req.authParameters, jwt)
}
