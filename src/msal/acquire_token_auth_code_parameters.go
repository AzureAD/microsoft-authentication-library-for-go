// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
)

// AcquireTokenAuthCodeParameters contains the parameters required to acquire an access token using the auth code flow.
type AcquireTokenAuthCodeParameters struct {
	commonParameters *acquireTokenCommonParameters
	redirectURI      string
	Code             string
	codeChallenge    string
	clientCredential *msalbase.ClientCredential
	requestType      requests.AuthCodeRequestType
}

// CreateAcquireTokenAuthCodeParameters creates an AcquireTokenAuthCodeParameters instance.
// Pass in the scopes required, the redirect URI for your application, as well as a code challenge.
// Code challenges are used to secure authorization code grants; for more information, visit
// https://tools.ietf.org/html/rfc7636.
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
