// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import "github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"

// AcquireTokenClientCredentialParameters contains the parameters required to acquire an access token using the client credential flow.
type AcquireTokenClientCredentialParameters struct {
	commonParameters *acquireTokenCommonParameters
}

// CreateAcquireTokenClientCredentialParameters creates an AcquireTokenClientCredentialParameters instance.
// Pass in the scopes required.
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
