// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"errors"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type AuthCodeRequestType int

const (
	AuthCodePublicClient AuthCodeRequestType = iota
	AuthCodeClientSecret
	AuthCodeClientAssertion
)

// AuthCodeRequest stores the values required to request a token from the authority using an authorization code
type AuthCodeRequest struct {
	webRequestManager IWebRequestManager
	authParameters    *msalbase.AuthParametersInternal
	Code              string
	CodeChallenge     string
	ClientSecret      string
	ClientAssertion   *msalbase.ClientAssertion
	RequestType       AuthCodeRequestType
}

// CreateAuthCodeRequest creates an instance of AuthCodeRequest
func CreateAuthCodeRequest(
	webRequestManager IWebRequestManager,
	authParameters *msalbase.AuthParametersInternal,
	reqType AuthCodeRequestType) *AuthCodeRequest {
	req := &AuthCodeRequest{
		webRequestManager: webRequestManager,
		authParameters:    authParameters,
		RequestType:       reqType,
	}
	return req
}

// Execute executes the auth code request and returns an access token or and error
func (req *AuthCodeRequest) Execute() (*msalbase.TokenResponse, error) {
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(req.authParameters.AuthorityInfo, "")
	if err != nil {
		return nil, err
	}
	req.authParameters.Endpoints = endpoints
	params := make(map[string]string)
	if req.RequestType == AuthCodeClientSecret {
		params["client_secret"] = req.ClientSecret
	} else if req.RequestType == AuthCodeClientAssertion {
		if req.ClientAssertion.ClientAssertionJWT == "" {
			if req.ClientAssertion.ClientCertificate != nil {
				jwt, err := req.ClientAssertion.ClientCertificate.BuildJWT(req.authParameters)
				if err != nil {
					return nil, err
				}
				req.ClientAssertion.ClientAssertionJWT = jwt
			} else {
				return nil, errors.New("No client assertion found")
			}
		}
		params["client_assertion"] = req.ClientAssertion.ClientAssertionJWT
		params["client_assertion_type"] = msalbase.ClientAssertionGrant
	}
	tokenResponse, err := req.webRequestManager.GetAccessTokenFromAuthCode(req.authParameters, req.Code, req.CodeChallenge, params)
	if err != nil {
		return nil, err
	}
	return tokenResponse, nil
}
