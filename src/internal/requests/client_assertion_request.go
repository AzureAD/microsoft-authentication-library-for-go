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

func CreateClientAssertionRequestWithJWT(webRequestManager IWebRequestManager,
	authParameters *msalbase.AuthParametersInternal, jwt string) *ClientAssertionRequest {
	req := &ClientAssertionRequest{
		webRequestManager: webRequestManager,
		authParameters:    authParameters,
		clientAssertion:   msalbase.CreateClientAssertionFromJWT(jwt),
	}
	return req
}

func CreateClientAssertionRequestWithCertificate(
	webRequestManager IWebRequestManager, authParameters *msalbase.AuthParametersInternal,
	thumbprint string, key []byte) *ClientAssertionRequest {
	req := &ClientAssertionRequest{
		webRequestManager: webRequestManager,
		authParameters:    authParameters,
		clientAssertion:   msalbase.CreateClientAssertionFromCertificate(thumbprint, key),
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
			return nil, errors.New("No assertion or certificate found")
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
