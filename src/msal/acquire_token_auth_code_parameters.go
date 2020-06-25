// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

// AcquireTokenAuthCodeParameters contains the parameters required to acquire an access token using the auth code flow
type AcquireTokenAuthCodeParameters struct {
	commonParameters    *acquireTokenCommonParameters
	redirectURI         string
	Code                string
	codeChallenge       string
	codeChallengeMethod string
}

// CreateAcquireTokenAuthCodeParameters creates an AcquireTokenAuthCodeParameters instance
func CreateAcquireTokenAuthCodeParameters(scopes []string,
	redirectURI string,
	codeChallenge string) *AcquireTokenAuthCodeParameters {
	p := &AcquireTokenAuthCodeParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		redirectURI:      redirectURI,
		codeChallenge:    codeChallenge,
	}
	return p
}

func (p *AcquireTokenAuthCodeParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.Redirecturi = p.redirectURI
	authParams.AuthorizationType = msalbase.AuthorizationTypeAuthCode
}
