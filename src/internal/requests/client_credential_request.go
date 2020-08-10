// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

type ClientCredentialRequest struct {
	webRequestManager IWebRequestManager
	authParameters    *msalbase.AuthParametersInternal
	clientCredential  *msalbase.ClientCredential
}

func CreateClientCredentialRequest(
	wrm IWebRequestManager,
	authParams *msalbase.AuthParametersInternal,
	clientCred *msalbase.ClientCredential) *ClientCredentialRequest {
	return &ClientCredentialRequest{wrm, authParams, clientCred}
}

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
	}
	if err != nil {
		return nil, err
	}
	return tokenResponse, nil
}
