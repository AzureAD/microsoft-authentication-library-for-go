// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

// AcquireTokenInteractiveParameters stuff
type AcquireTokenInteractiveParameters struct {
	commonParameters *acquireTokenCommonParameters
	redirectURI      string
	code             string
}

// CreateAcquireTokenInteractiveParameters stuff
func CreateAcquireTokenInteractiveParameters(scopes []string, redirectURI string) *AcquireTokenInteractiveParameters {
	p := &AcquireTokenInteractiveParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		redirectURI:      redirectURI,
	}
	return p
}

func (p *AcquireTokenInteractiveParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.SetRedirectURI(p.redirectURI)
	authParams.SetAuthorizationType(msalbase.AuthorizationTypeInteractive)
}

func (p *AcquireTokenInteractiveParameters) SetCode(code string) {
	p.code = code
}
