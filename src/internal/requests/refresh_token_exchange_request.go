// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

// RefreshTokenExchangeRequest stuff
type RefreshTokenExchangeRequest struct {
	webRequestManager IWebRequestManager
	cacheManager      ICacheManager
	authParameters    *msalbase.AuthParametersInternal
	refreshToken      msalbase.Credential
}

// CreateRefreshTokenExchangeRequest stuff
func CreateRefreshTokenExchangeRequest(
	webRequestManager IWebRequestManager,
	cacheManager ICacheManager,
	authParameters *msalbase.AuthParametersInternal,
	refreshToken msalbase.Credential) *RefreshTokenExchangeRequest {
	req := &RefreshTokenExchangeRequest{webRequestManager, cacheManager, authParameters, refreshToken}
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
	return req.webRequestManager.GetAccessTokenFromRefreshToken(req.authParameters, req.refreshToken.GetSecret())
}
