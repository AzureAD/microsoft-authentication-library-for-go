// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"errors"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type ClientAssertionRequest struct {
	webRequestManager IWebRequestManager
	authParameters    *msalbase.AuthParametersInternal
	clientAssertion   *msalbase.ClientAssertion
}

func CreateClientAssertionRequest(webRequestManager IWebRequestManager,
	authParameters *msalbase.AuthParametersInternal, assertion *msalbase.ClientAssertion) *ClientAssertionRequest {
	req := &ClientAssertionRequest{
		webRequestManager: webRequestManager,
		authParameters:    authParameters,
		clientAssertion:   assertion,
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
	if req.clientAssertion.ClientAssertionJWT == "" {
		if req.clientAssertion.ClientCertificate == nil {
			return nil, errors.New("no assertion or certificate found")
		}
		jwt, err := req.clientAssertion.ClientCertificate.BuildJWT(
			req.authParameters)
		if err != nil {
			return nil, err
		}
		req.clientAssertion.ClientAssertionJWT = jwt
	}
	tokenResponse, err := req.webRequestManager.GetAccessTokenWithAssertion(req.authParameters, req.clientAssertion.ClientAssertionJWT)
	if err != nil {
		return nil, err
	}
	return tokenResponse, nil
}
