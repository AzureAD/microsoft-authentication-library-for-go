// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

type AcquireTokenCertificateParameters struct {
	commonParameters *acquireTokenCommonParameters
	thumbprint       string
	privateKey       []byte
}

func CreateAcquireTokenCertificateParameters(scopes []string,
	thumbprint string, key []byte) *AcquireTokenCertificateParameters {
	params := &AcquireTokenCertificateParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		thumbprint:       thumbprint,
		privateKey:       key,
	}
	return params
}

func (p *AcquireTokenCertificateParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.AuthorizationType = msalbase.AuthorizationTypeClientCredentials
}
