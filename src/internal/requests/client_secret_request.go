// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

//ClientSecretRequest stores the values required to request a token from the authority using an secret (confidential client)
type ClientSecretRequest struct {
	webRequestManager WebRequestManager
	authParameters    *msalbase.AuthParametersInternal
	clientSecret      string
}

//CreateClientSecretRequest creates a ClientSecretRequest instance
func CreateClientSecretRequest(
	webRequestManager WebRequestManager,
	authParameters *msalbase.AuthParametersInternal,
	clientSecret string) *ClientSecretRequest {
	req := &ClientSecretRequest{
		webRequestManager: webRequestManager,
		authParameters:    authParameters,
		clientSecret:      clientSecret,
	}
	return req
}

//Execute executes the token acquisition requests and returns a token response or an error
func (req *ClientSecretRequest) Execute() (*msalbase.TokenResponse, error) {
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
