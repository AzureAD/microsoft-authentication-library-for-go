// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type ClientCredentialsRequest struct {
	webRequestManager IWebRequestManager
	authParameters    *msalbase.AuthParametersInternal
	clientSecret      string
}

func CreateClientCredentialsRequest(
	webRequestManager IWebRequestManager,
	authParameters *msalbase.AuthParametersInternal,
	clientSecret string) *ClientCredentialsRequest {
	req := &ClientCredentialsRequest{
		webRequestManager: webRequestManager,
		authParameters:    authParameters,
		clientSecret:      clientSecret,
	}
	return req
}

func (req *ClientCredentialsRequest) Execute() (*msalbase.TokenResponse, error) {
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(req.authParameters.AuthorityInfo, "")
	if err != nil {
		return nil, err
	}
	req.authParameters.Endpoints = endpoints
	tokenResponse, err := req.webRequestManager.GetAccessTokenWithClientSecret(req.authParameters, req.clientSecret)
	if err != nil {
		return nil, err
	}
	return tokenResponse, nil
}
