// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import "strings"

type AuthorizationCodeURLParameters struct {
	authParameters *AuthParametersInternal
	responseType   string
	responseMode   string
	state          string
	prompt         string
	loginHint      string
	domainHint     string
}

func CreateAuthorizationCodeURLParameters(authParams *AuthParametersInternal) *AuthorizationCodeURLParameters {
	p := &AuthorizationCodeURLParameters{authParameters: authParams, responseType: "code"}
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
