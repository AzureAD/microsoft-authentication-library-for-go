// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

//RefreshTokenReqType is whether the refresh token flow is for a public or confidential client
type RefreshTokenReqType int

//These are the different values for RefreshTokenReqType
const (
	RefreshTokenPublic RefreshTokenReqType = iota
	RefreshTokenConfidential
)

// RefreshTokenExchangeRequest stores the values required to request a token from the authority using a refresh token
type RefreshTokenExchangeRequest struct {
	webRequestManager WebRequestManager
	authParameters    *msalbase.AuthParametersInternal
	refreshToken      msalbase.Credential
	ClientCredential  *msalbase.ClientCredential
	RequestType       RefreshTokenReqType
}

// CreateRefreshTokenExchangeRequest creates a RefreshTokenExchangeRequest instance
func CreateRefreshTokenExchangeRequest(
	webRequestManager WebRequestManager,
	authParameters *msalbase.AuthParametersInternal,
	refreshToken msalbase.Credential,
	reqType RefreshTokenReqType) *RefreshTokenExchangeRequest {
	req := &RefreshTokenExchangeRequest{
		webRequestManager: webRequestManager,
		authParameters:    authParameters,
		refreshToken:      refreshToken,
		RequestType:       reqType,
	}
	return req
}

//Execute performs the token acquisition request and returns a token response or an error
func (req *RefreshTokenExchangeRequest) Execute() (*msalbase.TokenResponse, error) {
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(req.authParameters.AuthorityInfo, "")
	if err != nil {
		return nil, err
	}
	req.authParameters.Endpoints = endpoints
	params := make(map[string]string)
	if req.RequestType == RefreshTokenConfidential {
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
	return req.webRequestManager.GetAccessTokenFromRefreshToken(req.authParameters, req.refreshToken.GetSecret(), params)
}
