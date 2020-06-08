// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"net/url"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

// AuthCodeRequest stores the values required to request a token from the authority using an authorization code
type AuthCodeRequest struct {
	webRequestManager     IWebRequestManager
	cacheManager          msalbase.ICacheManager
	authParameters        *msalbase.AuthParametersInternal
	authCodeURLParameters *msalbase.AuthorizationCodeURLParameters
	code                  string
}

// CreateAuthCodeRequest creates an instance of AuthCodeRequest
func CreateAuthCodeRequest(
	webRequestManager IWebRequestManager,
	cacheManager msalbase.ICacheManager,
	authParameters *msalbase.AuthParametersInternal) *AuthCodeRequest {
	req := &AuthCodeRequest{webRequestManager, cacheManager, authParameters, nil, ""}
	return req
}

//SetCode sets the authorization code of this request
func (req *AuthCodeRequest) SetCode(code string) {
	req.code = code
}

//GetAuthURL returns the URL to go to to acquire the authorization code
func (req *AuthCodeRequest) GetAuthURL() (string, error) {
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(req.authParameters.GetAuthorityInfo(), "")
	if err != nil {
		return "", err
	}
	req.authParameters.SetAuthorityEndpoints(endpoints)
	req.authCodeURLParameters = msalbase.CreateAuthorizationCodeURLParameters(req.authParameters)
	return req.buildURL()
}

func (req *AuthCodeRequest) buildURL() (string, error) {
	authCodeURLParameters := req.authCodeURLParameters
	baseURL, err := url.Parse(req.authParameters.GetAuthorityEndpoints().GetAuthorizationEndpoint())
	if err != nil {
		return "", err
	}
	urlParams := url.Values{}
	urlParams.Add("client_id", authCodeURLParameters.GetAuthParameters().GetClientID())
	urlParams.Add("response_type", authCodeURLParameters.GetResponseType())
	urlParams.Add("redirect_uri", authCodeURLParameters.GetAuthParameters().GetRedirectURI())
	urlParams.Add("scope", authCodeURLParameters.GetSpaceSeparatedScopes())
	baseURL.RawQuery = urlParams.Encode()
	return baseURL.String(), nil
}

// Execute executes the auth code request and returns an access token or and error
func (req *AuthCodeRequest) Execute() (*msalbase.TokenResponse, error) {
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(req.authParameters.GetAuthorityInfo(), "")
	if err != nil {
		return nil, err
	}
	req.authParameters.SetAuthorityEndpoints(endpoints)
	tokenResponse, err := req.webRequestManager.GetAccessTokenFromAuthCode(req.authParameters, req.code)
	if err != nil {
		return nil, err
	}
	return tokenResponse, nil
}
