// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
)

// AcquireTokenSilentParameters contains the parameters to acquire a token silently (from cache).
type AcquireTokenSilentParameters struct {
	commonParameters *acquireTokenCommonParameters
	account          AccountInterfacer
	requestType      requests.RefreshTokenReqType
	clientCredential *msalbase.ClientCredential
}

//CreateAcquireTokenSilentParameters creates an AcquireTokenSilentParameters instance with an empty account.
// This can be used in the case where tokens are acquired as the application instelf.
func CreateAcquireTokenSilentParameters(scopes []string) *AcquireTokenSilentParameters {
	p := &AcquireTokenSilentParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		account:          &msalbase.Account{},
	}
	return p
}

// CreateAcquireTokenSilentParametersWithAccount creates an AcquireTokenSilentParameters instance from an account.
// This account can be pulled from the cache.
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
