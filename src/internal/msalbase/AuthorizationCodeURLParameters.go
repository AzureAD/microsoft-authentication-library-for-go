// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import "strings"

type AuthorizationCodeURLParameters struct {
	authParameters      *AuthParametersInternal
	responseType        string
	responseMode        string
	state               string
	prompt              string
	loginHint           string
	domainHint          string
	codeChallenge       string
	codeChallengeMethod string
}

func CreateAuthorizationCodeURLParameters(authParams *AuthParametersInternal,
	codeChallenge string,
	codeChallengeMethod string) *AuthorizationCodeURLParameters {
	p := &AuthorizationCodeURLParameters{
		authParameters:      authParams,
		responseType:        "code",
		codeChallenge:       codeChallenge,
		codeChallengeMethod: codeChallengeMethod,
	}
	return p
}

func (p *AuthorizationCodeURLParameters) GetAuthParameters() *AuthParametersInternal {
	return p.authParameters
}

func (p *AuthorizationCodeURLParameters) GetResponseType() string {
	return p.responseType
}

func (p *AuthorizationCodeURLParameters) GetSpaceSeparatedScopes() string {
	return strings.Join(p.authParameters.GetScopes(), " ")
}

func (p *AuthorizationCodeURLParameters) GetCodeChallenge() string {
	return p.codeChallenge
}

func (p *AuthorizationCodeURLParameters) GetCodeChallengeMethod() string {
	return p.codeChallengeMethod
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
