// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

//AcquireTokenClientSecretParameters contains the parameters required to acquire a token using a client secret
type AcquireTokenClientSecretParameters struct {
	commonParameters *acquireTokenCommonParameters
}

//CreateAcquireTokenClientSecretParameters creates an AcquireTokenClientSecretParameters instance
func CreateAcquireTokenClientSecretParameters(scopes []string) *AcquireTokenClientSecretParameters {
	params := &AcquireTokenClientSecretParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
	}
	return params
}

func (p *AcquireTokenClientSecretParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.AuthorizationType = msalbase.AuthorizationTypeClientCredentials
}
