// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

type AcquireTokenClientAssertionParameters struct {
	commonParameters *acquireTokenCommonParameters
}

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
