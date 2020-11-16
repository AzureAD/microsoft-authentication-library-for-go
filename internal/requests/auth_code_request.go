// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"fmt"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

//AuthCodeRequestType is whether the authorization code flow is for a public or confidential client
type AuthCodeRequestType int

//These are the different values for AuthCodeRequestType
const (
	AuthCodePublic AuthCodeRequestType = iota
	AuthCodeConfidential
)

// AuthCodeRequest stores the values required to request a token from the authority using an authorization code
type AuthCodeRequest struct {
	webRequestManager WebRequestManager
	authParameters    msalbase.AuthParametersInternal
	Code              string
	CodeChallenge     string
	ClientCredential  msalbase.ClientCredential
	RequestType       AuthCodeRequestType
}

// CreateAuthCodeRequest creates an instance of AuthCodeRequest
func CreateAuthCodeRequest(webRequestManager WebRequestManager, authParameters msalbase.AuthParametersInternal, reqType AuthCodeRequestType) *AuthCodeRequest {
	return &AuthCodeRequest{
		webRequestManager: webRequestManager,
		authParameters:    authParameters,
		RequestType:       reqType,
	}
}

//Execute performs the token acquisition request and returns a token response or an error
func (req *AuthCodeRequest) Execute() (msalbase.TokenResponse, error) {
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(req.authParameters.AuthorityInfo, "")
	if err != nil {
		return msalbase.TokenResponse{}, fmt.Errorf("unable to resolve endpoints: %w", err)
	}

	req.authParameters.Endpoints = endpoints
	params := make(map[string]string)
	if req.RequestType == AuthCodeConfidential {
		if req.ClientCredential.GetCredentialType() == msalbase.ClientCredentialSecret {
			params["client_secret"] = req.ClientCredential.GetSecret()
		} else {
			jwt, err := req.ClientCredential.GetAssertion().GetJWT(req.authParameters)
			if err != nil {
				return msalbase.TokenResponse{}, fmt.Errorf("unable to retrieve JWT from client credentials: %w", err)
			}
			params["client_assertion"] = jwt
			params["client_assertion_type"] = msalbase.ClientAssertionGrant
		}
	}
	tokenResponse, err := req.webRequestManager.GetAccessTokenFromAuthCode(req.authParameters, req.Code, req.CodeChallenge, params)
	if err != nil {
		return msalbase.TokenResponse{}, fmt.Errorf("could not retrieve token from auth code: %w", err)
	}
	return tokenResponse, nil
}
