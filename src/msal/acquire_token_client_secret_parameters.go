// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

type AcquireTokenClientSecretParameters struct {
	commonParameters *acquireTokenCommonParameters
	clientSecret     string
}

func CreateAcquireTokenClientSecretParameters(scopes []string,
	clientSecret string) *AcquireTokenClientSecretParameters {
	params := &AcquireTokenClientSecretParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		clientSecret:     clientSecret,
	}
	return params
}

func (p *AcquireTokenClientSecretParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.AuthorizationType = msalbase.AuthorizationTypeClientCredentials
}
