// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

// AuthCodeRequest stores the values required to request a token from the authority using an authorization code
type AuthCodeRequest struct {
	webRequestManager IWebRequestManager
	cacheManager      msalbase.ICacheManager
	authParameters    *msalbase.AuthParametersInternal
	Code              string
	CodeChallenge     string
}

// CreateAuthCodeRequest creates an instance of AuthCodeRequest
func CreateAuthCodeRequest(
	webRequestManager IWebRequestManager,
	cacheManager msalbase.ICacheManager,
	authParameters *msalbase.AuthParametersInternal) *AuthCodeRequest {
	req := &AuthCodeRequest{
		webRequestManager: webRequestManager,
		cacheManager:      cacheManager,
		authParameters:    authParameters}
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
	tokenResponse, err := req.webRequestManager.GetAccessTokenFromAuthCode(req.authParameters, req.Code, req.CodeChallenge)
	if err != nil {
		return nil, err
	}
	return tokenResponse, nil
}
