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
type acquireTokenAuthCodeParameters struct {
	commonParameters *acquireTokenCommonParameters
	Code             string
	CodeChallenge    string
	clientCredential *msalbase.ClientCredential
	requestType      requests.AuthCodeRequestType
}

// createAcquireTokenAuthCodeParameters creates an AcquireTokenAuthCodeParameters instance.
// Pass in the scopes required, the redirect URI for your application.
func createAcquireTokenAuthCodeParameters(scopes []string) *acquireTokenAuthCodeParameters {
	return &acquireTokenAuthCodeParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
	}
}

func (p *acquireTokenAuthCodeParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.Redirecturi = "https://login.microsoftonline.com/common/oauth2/nativeclient"
	authParams.AuthorizationType = msalbase.AuthorizationTypeAuthCode
}
