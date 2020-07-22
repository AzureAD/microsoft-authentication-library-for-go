// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

type ClientAssertionRequest struct {
	webRequestManager IWebRequestManager
	authParameters    *msalbase.AuthParametersInternal
	clientAssertion   *msalbase.ClientAssertion
}

func CreateClientAssertionRequestWithJWT(webRequestManager IWebRequestManager,
	authParameters *msalbase.AuthParametersInternal, jwt string) *ClientAssertionRequest {
	req := &ClientAssertionRequest{
		webRequestManager: webRequestManager,
		authParameters:    authParameters,
		clientAssertion:   msalbase.CreateClientAssertionFromJWT(jwt),
	}
	return req
}

func (req *ClientAssertionRequest) Execute() (*msalbase.TokenResponse, error) {
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(req.authParameters.AuthorityInfo, "")
	if err != nil {
		return nil, err
	}
	req.authParameters.Endpoints = endpoints
	tokenResponse, err := req.webRequestManager.GetAccessTokenWithAssertion(req.authParameters, req.clientAssertion.ClientAssertionJWT)
	if err != nil {
		return nil, err
	}
	return tokenResponse, nil
}
