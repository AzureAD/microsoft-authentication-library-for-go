// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"net/url"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
)

// AuthorizationCodeURLParameters has the parameters to create the URL to generate an authorization code.
type AuthorizationCodeURLParameters struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	ResponseMode        string
	State               string
	Prompt              string
	LoginHint           string
	DomainHint          string
	CodeChallenge       string
	CodeChallengeMethod string
	Scopes              []string
}

// CreateAuthorizationCodeURLParameters creates an AuthorizationCodeURLParameters instance. These are the basic required parameters to create this URL.
// However, if you want other parameters to be in the URL, you can just set the fields of the struct.
func CreateAuthorizationCodeURLParameters(clientID string, redirectURI string, scopes []string) *AuthorizationCodeURLParameters {
	p := &AuthorizationCodeURLParameters{
		ClientID:     clientID,
		ResponseType: msalbase.DefaultAuthCodeResponseType,
		RedirectURI:  redirectURI,
		Scopes:       scopes,
	}
	return p
}

// createURL creates the URL required to generate an authorization code from the parameters.
func (p *AuthorizationCodeURLParameters) createURL(wrm requests.WebRequestManager, authParams *msalbase.AuthParametersInternal) (string, error) {
	resolutionManager := requests.CreateAuthorityEndpointResolutionManager(wrm)
	endpoints, err := resolutionManager.ResolveEndpoints(authParams.AuthorityInfo, "")
	if err != nil {
		return "", err
	}
	baseURL, err := url.Parse(endpoints.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	urlParams := url.Values{}
	urlParams.Add("client_id", p.ClientID)
	urlParams.Add("response_type", p.ResponseType)
	urlParams.Add("redirect_uri", p.RedirectURI)
	urlParams.Add("scope", p.getSeparatedScopes())
	if p.CodeChallenge != "" {
		urlParams.Add("code_challenge", p.CodeChallenge)
	}
	if p.State != "" {
		urlParams.Add("state", p.State)
	}
	if p.ResponseMode != "" {
		urlParams.Add("response_mode", p.ResponseMode)
	}
	if p.Prompt != "" {
		urlParams.Add("prompt", p.Prompt)
	}
	if p.LoginHint != "" {
		urlParams.Add("login_hint", p.LoginHint)
	}
	if p.DomainHint != "" {
		urlParams.Add("domain_hint", p.DomainHint)
	}
	if p.CodeChallengeMethod != "" {
		urlParams.Add("code_challenge_method", p.CodeChallengeMethod)
	}
	baseURL.RawQuery = urlParams.Encode()
	return baseURL.String(), nil
}

func (p *AuthorizationCodeURLParameters) getSeparatedScopes() string {
	return msalbase.ConcatenateScopes(p.Scopes)
}
