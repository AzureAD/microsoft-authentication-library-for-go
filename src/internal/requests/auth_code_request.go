// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type AuthCodeRequestType int

const (
	AuthCodePublic AuthCodeRequestType = iota
	AuthCodeConfidential
)

// AuthCodeRequest stores the values required to request a token from the authority using an authorization code
type AuthCodeRequest struct {
	webRequestManager IWebRequestManager
	authParameters    *msalbase.AuthParametersInternal
	Code              string
	CodeChallenge     string
	ClientCredential  *msalbase.ClientCredential
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
	if req.RequestType == AuthCodeConfidential {
		if req.ClientCredential.GetCredentialType() == msalbase.ClientCredentialSecret {
			params["client_secret"] = req.ClientCredential.GetSecret()
		} else {
			jwt, err := req.ClientCredential.GetAssertion().GetJWT(req.authParameters)
			if err != nil {
				return nil, err
			}
			params["client_assertion"] = jwt
			params["client_assertion_type"] = msalbase.ClientAssertionGrant
		}
	}
	tokenResponse, err := req.webRequestManager.GetAccessTokenFromAuthCode(req.authParameters, req.Code, req.CodeChallenge, params)
	if err != nil {
		return nil, err
	}
	return tokenResponse, nil
}
