// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "internal/msalbase"

// AcquireTokenUsernamePasswordParameters stuff
type AcquireTokenUsernamePasswordParameters struct {
	commonParameters *acquireTokenCommonParameters
	username         string
	password         string
}

// CreateAcquireTokenUsernamePasswordParameters stuff
func CreateAcquireTokenUsernamePasswordParameters(scopes []string, username string, password string) *AcquireTokenUsernamePasswordParameters {
	p := &AcquireTokenUsernamePasswordParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		username:         username,
		password:         password,
	}
	return p
}

// SetUsername stuff
func (p *AcquireTokenUsernamePasswordParameters) SetUsername(username string) {
	p.username = username
}

func (p *AcquireTokenUsernamePasswordParameters) GetUsername() string {
	return p.username
}

// SetPassword stuff
func (p *AcquireTokenUsernamePasswordParameters) SetPassword(password string) {
	p.password = password
}

func (p *AcquireTokenUsernamePasswordParameters) GetPassword() string {
	return p.password
}

func (p *AcquireTokenUsernamePasswordParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.SetAuthorizationType(msalbase.AuthorizationTypeUsernamePassword)
	authParams.SetUsername(p.GetUsername())
	authParams.SetPassword(p.GetPassword())
}
