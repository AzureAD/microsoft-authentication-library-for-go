// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

// AuthCodeRequest stores the values required to request a token from the authority using an authorization code
type AuthCodeRequest struct {
	webRequestManager IWebRequestManager
	authParameters    *msalbase.AuthParametersInternal
	Code              string
	CodeChallenge     string
	ClientSecret      string
}

// CreateAuthCodeRequest creates an instance of AuthCodeRequest
func CreateAuthCodeRequest(
	webRequestManager IWebRequestManager,
	authParameters *msalbase.AuthParametersInternal) *AuthCodeRequest {
	req := &AuthCodeRequest{
		webRequestManager: webRequestManager,
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
	tokenResponse, err := req.webRequestManager.GetAccessTokenFromAuthCode(req.authParameters, req.Code, req.CodeChallenge, req.ClientSecret)
	if err != nil {
		return nil, err
	}
	return tokenResponse, nil
}
