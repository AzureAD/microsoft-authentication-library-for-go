// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

// AcquireTokenSilentParameters contains the parameters to acquire a token silently
type AcquireTokenSilentParameters struct {
	commonParameters *acquireTokenCommonParameters
	account          AccountInterfacer
}

//CreateAcquireTokenSilentParameters creates an AcquireTokenSilentParameters instance with an empty account
func CreateAcquireTokenSilentParameters(scopes []string) *AcquireTokenSilentParameters {
	p := &AcquireTokenSilentParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		account:          &msalbase.Account{},
	}
	return p
}

// CreateAcquireTokenSilentParametersWithAccount creates an AcquireTokenSilentParameters instance from an account
func CreateAcquireTokenSilentParametersWithAccount(scopes []string, account AccountInterfacer) *AcquireTokenSilentParameters {
	p := &AcquireTokenSilentParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		account:          account,
	}
	return p
}

func (p *AcquireTokenSilentParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.AuthorizationType = msalbase.AuthorizationTypeRefreshTokenExchange
	authParams.HomeaccountID = p.account.GetHomeAccountID()
}
