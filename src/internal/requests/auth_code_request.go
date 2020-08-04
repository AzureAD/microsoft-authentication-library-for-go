// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"errors"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

//AuthCodeRequestType is whether the authorization code flow is for a public client,
// or is for a confidential client and uses a secret or assertion
type AuthCodeRequestType int

//These are the different values for AuthCodeRequestType
const (
	AuthCodePublicClient AuthCodeRequestType = iota
	AuthCodeClientSecret
	AuthCodeClientAssertion
)

// AuthCodeRequest stores the values required to request a token from the authority using an authorization code
type AuthCodeRequest struct {
	webRequestManager WebRequestManager
	authParameters    *msalbase.AuthParametersInternal
	Code              string
	CodeChallenge     string
	ClientSecret      string
	ClientAssertion   *msalbase.ClientAssertion
	RequestType       AuthCodeRequestType
}

// CreateAuthCodeRequest creates an instance of AuthCodeRequest
func CreateAuthCodeRequest(
	webRequestManager WebRequestManager,
	authParameters *msalbase.AuthParametersInternal,
	reqType AuthCodeRequestType) *AuthCodeRequest {
	req := &AuthCodeRequest{
		webRequestManager: webRequestManager,
		authParameters:    authParameters,
		RequestType:       reqType,
	}
	return req
}

//Execute executes the token acquisition request and returns a token response or an error
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
