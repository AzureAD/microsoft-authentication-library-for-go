// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

type AcquireTokenClientCredentialsParameters struct {
	commonParameters *acquireTokenCommonParameters
	clientSecret     string
}

func CreateAcquireTokenClientCredentialsParameters(scopes []string,
	clientSecret string) *AcquireTokenClientCredentialsParameters {
	params := &AcquireTokenClientCredentialsParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		clientSecret:     clientSecret,
	}
	return params
}

func (p *AcquireTokenClientCredentialsParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.AuthorizationType = msalbase.AuthorizationTypeClientCredentials
}
