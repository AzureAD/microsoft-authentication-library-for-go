// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"net/url"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
)

type AuthorizationCodeURLParameters struct {
	clientID            string
	redirectURI         string
	responseType        string
	responseMode        string
	state               string
	prompt              string
	loginHint           string
	domainHint          string
	codeChallenge       string
	codeChallengeMethod string
	scopes              []string
}

func CreateAuthorizationCodeURLParameters(clientID string, redirectURI string, scopes []string, codeChallenge string) *AuthorizationCodeURLParameters {
	p := &AuthorizationCodeURLParameters{
		clientID:      clientID,
		responseType:  msalbase.DefaultAuthCodeResponseType,
		redirectURI:   redirectURI,
		scopes:        scopes,
		codeChallenge: codeChallenge,
	}
	return p
}

func (p *AuthorizationCodeURLParameters) CreateURL(wrm requests.IWebRequestManager, authParams *msalbase.AuthParametersInternal) (string, error) {
	resolutionManager := requests.CreateAuthorityEndpointResolutionManager(wrm)
	endpoints, err := resolutionManager.ResolveEndpoints(authParams.GetAuthorityInfo(), "")
	if err != nil {
		return "", err
	}
	baseURL, err := url.Parse(endpoints.GetAuthorizationEndpoint())
	if err != nil {
		return "", err
	}
	urlParams := url.Values{}
	urlParams.Add("client_id", p.clientID)
	urlParams.Add("response_type", p.responseType)
	urlParams.Add("redirect_uri", p.redirectURI)
	urlParams.Add("scope", p.GetSpaceSeparatedScopes())
	urlParams.Add("code_challenge", p.codeChallenge)
	if p.state != "" {
		urlParams.Add("state", p.state)
	}
	if p.responseMode != "" {
		urlParams.Add("response_mode", p.responseMode)
	}
	if p.prompt != "" {
		urlParams.Add("prompt", p.prompt)
	}
	if p.loginHint != "" {
		urlParams.Add("login_hint", p.loginHint)
	}
	if p.domainHint != "" {
		urlParams.Add("domain_hint", p.domainHint)
	}
	if p.codeChallengeMethod != "" {
		urlParams.Add("code_challenge_method", p.codeChallengeMethod)
	}
	baseURL.RawQuery = urlParams.Encode()
	return baseURL.String(), nil
}

func (p *AuthorizationCodeURLParameters) GetResponseType() string {
	return p.responseType
}

func (p *AuthorizationCodeURLParameters) GetSpaceSeparatedScopes() string {
	return strings.Join(p.scopes, msalbase.DefaultScopeSeparator)
}

func (p *AuthorizationCodeURLParameters) GetCodeChallenge() string {
	return p.codeChallenge
}

func (p *AuthorizationCodeURLParameters) GetCodeChallengeMethod() string {
	return p.codeChallengeMethod
}

func (p *AuthorizationCodeURLParameters) SetCodeChallengMethod(codeChallengeMethod string) {
	p.codeChallengeMethod = codeChallengeMethod
}

func (p *AuthorizationCodeURLParameters) GetResponseMode() string {
	return p.responseMode
}

func (p *AuthorizationCodeURLParameters) SetResponseMode(responseMode string) {
	p.responseMode = responseMode
}

func (p *AuthorizationCodeURLParameters) GetState() string {
	return p.state
}

func (p *AuthorizationCodeURLParameters) SetState(state string) {
	p.state = state
}

func (p *AuthorizationCodeURLParameters) GetPrompt() string {
	return p.prompt
}

func (p *AuthorizationCodeURLParameters) SetPrompt(prompt string) {
	p.prompt = prompt
}

func (p *AuthorizationCodeURLParameters) GetLoginHint() string {
	return p.loginHint
}

func (p *AuthorizationCodeURLParameters) SetLoginHint(loginHint string) {
	p.loginHint = loginHint
}

func (p *AuthorizationCodeURLParameters) GetDomainHint() string {
	return p.domainHint
}

func (p *AuthorizationCodeURLParameters) SetDomainHint(domainHint string) {
	p.domainHint = domainHint
}
