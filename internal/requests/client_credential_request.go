// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import "github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"

//ClientCredentialRequest stores the values required to acquire a token from the authority using a client credentials grant
type ClientCredentialRequest struct {
	webRequestManager WebRequestManager
	authParameters    *msalbase.AuthParametersInternal
	clientCredential  *msalbase.ClientCredential
}

//CreateClientCredentialRequest creates an instance of ClientCredentialRequest
func CreateClientCredentialRequest(
	wrm WebRequestManager,
	authParams *msalbase.AuthParametersInternal,
	clientCred *msalbase.ClientCredential) *ClientCredentialRequest {
	return &ClientCredentialRequest{wrm, authParams, clientCred}
}

//Execute performs the token acquisition request and returns a token response or an error
func (req *ClientCredentialRequest) Execute() (*msalbase.TokenResponse, error) {
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(req.authParameters.AuthorityInfo, "")
	if err != nil {
		return nil, err
	}
	req.authParameters.Endpoints = endpoints
	var tokenResponse *msalbase.TokenResponse
	if req.clientCredential.GetCredentialType() == msalbase.ClientCredentialSecret {
		tokenResponse, err = req.webRequestManager.GetAccessTokenWithClientSecret(req.authParameters, req.clientCredential.GetSecret())
	} else {
		jwt, err := req.clientCredential.GetAssertion().GetJWT(req.authParameters)
		if err != nil {
			return nil, err
		}
		tokenResponse, err = req.webRequestManager.GetAccessTokenWithAssertion(req.authParameters, jwt)
		if err != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}
	return tokenResponse, nil
}
