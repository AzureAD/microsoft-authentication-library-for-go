// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

// AcquireTokenAuthCodeParameters contains the parameters required to acquire an access token using the auth code flow
type AcquireTokenAuthCodeParameters struct {
	commonParameters    *acquireTokenCommonParameters
	redirectURI         string
	code                string
	codeChallenge       string
	codeChallengeMethod string
}

// CreateAcquireTokenAuthCodeParameters creates an AcquireTokenAuthCodeParameters instance
func CreateAcquireTokenAuthCodeParameters(scopes []string,
	redirectURI string,
	codeChallenge string,
	codeChallengeMethod string) *AcquireTokenAuthCodeParameters {
	p := &AcquireTokenAuthCodeParameters{
		commonParameters:    createAcquireTokenCommonParameters(scopes),
		redirectURI:         redirectURI,
		codeChallenge:       codeChallenge,
		codeChallengeMethod: codeChallengeMethod,
	}
	return p
}

func (p *AcquireTokenAuthCodeParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.SetRedirectURI(p.redirectURI)
	authParams.SetAuthorizationType(msalbase.AuthorizationTypeAuthCode)
}

//SetCode sets the auth code for the request
func (p *AcquireTokenAuthCodeParameters) SetCode(code string) {
	p.code = code
}

func (p *AcquireTokenAuthCodeParameters) SetCodeChallenge(codeChallenge string) {
	p.codeChallenge = codeChallenge
}

func (p *AcquireTokenAuthCodeParameters) SetCodeChallengeMethod(codeChallengeMethod string) {
	p.codeChallengeMethod = codeChallengeMethod
}
