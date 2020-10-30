// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import "github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"

// AcquireTokenClientCredentialParameters contains the parameters required to acquire an access token using the client credential flow.
type acquireTokenClientCredentialParameters struct {
	commonParameters *acquireTokenCommonParameters
}

// CreateAcquireTokenClientCredentialParameters creates an AcquireTokenClientCredentialParameters instance.
// Pass in the scopes required.
func createAcquireTokenClientCredentialParameters(scopes []string) *acquireTokenClientCredentialParameters {
	return &acquireTokenClientCredentialParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
	}
}

func (p *acquireTokenClientCredentialParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.AuthorizationType = msalbase.AuthorizationTypeClientCredentials
}
