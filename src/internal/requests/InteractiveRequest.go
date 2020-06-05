// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"net/url"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

// InteractiveRequest stuff
type InteractiveRequest struct {
	webRequestManager     IWebRequestManager
	cacheManager          msalbase.ICacheManager
	authParameters        *msalbase.AuthParametersInternal
	authCodeURLParameters *msalbase.AuthorizationCodeURLParameters
	code                  string
}

// CreateInteractiveRequest stuff
func CreateInteractiveRequest(
	webRequestManager IWebRequestManager,
	cacheManager msalbase.ICacheManager,
	authParameters *msalbase.AuthParametersInternal) *InteractiveRequest {
	req := &InteractiveRequest{webRequestManager, cacheManager, authParameters, nil, ""}
	return req
}

func (req *InteractiveRequest) SetCode(code string) {
	req.code = code
}

func (req *InteractiveRequest) GetAuthURL() (string, error) {
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(req.authParameters.GetAuthorityInfo(), "")
	if err != nil {
		return "", err
	}
	req.authParameters.SetAuthorityEndpoints(endpoints)
	req.authCodeURLParameters = msalbase.CreateAuthorizationCodeURLParameters(req.authParameters)
	return req.buildURL()
}

func (req *InteractiveRequest) buildURL() (string, error) {
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

// Execute stuff
func (req *InteractiveRequest) Execute() (*msalbase.TokenResponse, error) {
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
