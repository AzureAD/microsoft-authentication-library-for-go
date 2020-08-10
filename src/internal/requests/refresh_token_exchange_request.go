// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type RefreshTokenReqType int

const (
	RefreshTokenPublic RefreshTokenReqType = iota
	RefreshTokenConfidential
)

// RefreshTokenExchangeRequest stuff
type RefreshTokenExchangeRequest struct {
	webRequestManager IWebRequestManager
	authParameters    *msalbase.AuthParametersInternal
	refreshToken      msalbase.Credential
	ClientCredential  *msalbase.ClientCredential
	RequestType       RefreshTokenReqType
}

// CreateRefreshTokenExchangeRequest stuff
func CreateRefreshTokenExchangeRequest(
	webRequestManager IWebRequestManager,
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

// Execute stuff
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
