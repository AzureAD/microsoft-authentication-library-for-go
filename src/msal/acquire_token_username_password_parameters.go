// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

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

func (p *AcquireTokenUsernamePasswordParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.AuthorizationType = msalbase.AuthorizationTypeUsernamePassword
	authParams.Username = p.username
	authParams.Password = p.password
}
