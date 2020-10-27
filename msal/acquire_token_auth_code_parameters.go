// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
)

// AcquireTokenAuthCodeParameters contains the parameters required to acquire an access token using the auth code flow.
// To use PKCE, set the CodeChallengeParameter.
// Code challenges are used to secure authorization code grants; for more information, visit
// https://tools.ietf.org/html/rfc7636.
type AcquireTokenAuthCodeParameters struct {
	commonParameters *acquireTokenCommonParameters
	redirectURI      string
	Code             string
	CodeChallenge    string
	clientCredential *msalbase.ClientCredential
	requestType      requests.AuthCodeRequestType
}

// CreateAcquireTokenAuthCodeParameters creates an AcquireTokenAuthCodeParameters instance.
// Pass in the scopes required and the redirect URI for your application.
func CreateAcquireTokenAuthCodeParameters(scopes []string, redirectURI string) *AcquireTokenAuthCodeParameters {
	return &AcquireTokenAuthCodeParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		redirectURI:      redirectURI,
	}
}

func (p *AcquireTokenAuthCodeParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.Redirecturi = p.redirectURI
	authParams.AuthorizationType = msalbase.AuthorizationTypeAuthCode
}
