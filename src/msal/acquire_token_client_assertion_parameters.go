// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

//AcquireTokenClientAssertionParameters contains the parameters required to acquire a token using a client assertion
type AcquireTokenClientAssertionParameters struct {
	commonParameters *acquireTokenCommonParameters
}

//CreateAcquireTokenClientAssertionParameters creates an AcquireTokenClientAssertionParameters instance
func CreateAcquireTokenClientAssertionParameters(scopes []string) *AcquireTokenClientAssertionParameters {
	params := &AcquireTokenClientAssertionParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
	}
	return params
}

func (p *AcquireTokenClientAssertionParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.AuthorizationType = msalbase.AuthorizationTypeClientCredentials
}
