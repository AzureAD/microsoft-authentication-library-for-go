// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import "github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"

// AcquireTokenUsernamePasswordParameters contains the parameters required to acquire an access token using a username and password.
type AcquireTokenUsernamePasswordParameters struct {
	commonParameters *acquireTokenCommonParameters
	username         string
	password         string
}

// CreateAcquireTokenUsernamePasswordParameters creates an AcquireTokenUsernamePasswordParameters instance.
// Pass in the scopes as well as the user's username and password.
func CreateAcquireTokenUsernamePasswordParameters(scopes []string, username string, password string) *AcquireTokenUsernamePasswordParameters {
	return &AcquireTokenUsernamePasswordParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		username:         username,
		password:         password,
	}
}

func (p *AcquireTokenUsernamePasswordParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.AuthorizationType = msalbase.AuthorizationTypeUsernamePassword
	authParams.Username = p.username
	authParams.Password = p.password
}
