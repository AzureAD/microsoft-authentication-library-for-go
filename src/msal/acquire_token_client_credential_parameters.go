// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

type AcquireTokenClientCredentialParameters struct {
	commonParameters *acquireTokenCommonParameters
}

func CreateAcquireTokenClientCredentialParameters(scopes []string) *AcquireTokenClientCredentialParameters {
	params := &AcquireTokenClientCredentialParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
	}
	return params
}

func (p *AcquireTokenClientCredentialParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.AuthorizationType = msalbase.AuthorizationTypeClientCredentials
}
