// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

// AcquireTokenSilentOptions contains the optional parameters to acquire a token silently (from cache).
type AcquireTokenSilentOptions struct {
	// Account specifies the account to use when acquiring a token from the cache.
	Account *msalbase.Account
}

// CreateAcquireTokenSilentParameters creates an AcquireTokenSilentParameters instance with an empty account.
// This can be used in the case where tokens are acquired as the application instelf.
func CreateAcquireTokenSilentParameters(scopes []string) *AcquireTokenSilentParameters {
	p := &AcquireTokenSilentParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		account:          &msalbase.Account{},
	}
	return p
}

// CreateAcquireTokenSilentParametersWithAccount creates an AcquireTokenSilentParameters instance from an account.
// This account can be pulled from the cache by calling GetAccounts
func CreateAcquireTokenSilentParametersWithAccount(scopes []string, account AccountProvider) *AcquireTokenSilentParameters {
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
