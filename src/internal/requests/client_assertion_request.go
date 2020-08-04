// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"errors"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

//ClientAssertionRequest stores the values required to request a token from the authority using an assertion (confidential client)
type ClientAssertionRequest struct {
	webRequestManager WebRequestManager
	authParameters    *msalbase.AuthParametersInternal
	clientAssertion   *msalbase.ClientAssertion
}

//CreateClientAssertionRequest creates a ClientAssertionRequest instance
func CreateClientAssertionRequest(webRequestManager WebRequestManager,
	authParameters *msalbase.AuthParametersInternal, assertion *msalbase.ClientAssertion) *ClientAssertionRequest {
	req := &ClientAssertionRequest{
		webRequestManager: webRequestManager,
		authParameters:    authParameters,
		clientAssertion:   assertion,
	}
	return req
}

//Execute executes the token acquisition requests and returns a token response or an error
func (req *ClientAssertionRequest) Execute() (*msalbase.TokenResponse, error) {
	//Getting the token endpoint
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(req.authParameters.AuthorityInfo, "")
	if err != nil {
		return nil, err
	}
	req.authParameters.Endpoints = endpoints
	// Checking if an assertion JWT exists
	if req.clientAssertion.ClientAssertionJWT == "" {
		// If no JWT exists, checking if there is a certificate
		if req.clientAssertion.ClientCertificate == nil {
			return nil, errors.New("no assertion or certificate found")
		}
		//Building a JWT from a certificate instance
		jwt, err := req.clientAssertion.ClientCertificate.BuildJWT(
			req.authParameters)
		if err != nil {
			return nil, err
		}
		req.clientAssertion.ClientAssertionJWT = jwt
		// Check if the assertion is built from an expired certificate
	} else if req.clientAssertion.ClientCertificate != nil &&
		req.clientAssertion.ClientCertificate.IsExpired() {
		jwt, err := req.clientAssertion.ClientCertificate.BuildJWT(req.authParameters)
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
