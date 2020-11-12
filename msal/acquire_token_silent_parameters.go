// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
)

// AcquireTokenSilentParameters contains the parameters to acquire a token silently (from cache).
type AcquireTokenSilentParameters struct {
	commonParameters acquireTokenCommonParameters
	account          AccountProvider
	requestType      requests.RefreshTokenReqType
	clientCredential msalbase.ClientCredential
}

// CreateAcquireTokenSilentParameters creates an AcquireTokenSilentParameters instance with an empty account.
// This can be used in the case where tokens are acquired as the application instelf.
func CreateAcquireTokenSilentParameters(scopes []string) AcquireTokenSilentParameters {
	p := AcquireTokenSilentParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		account:          msalbase.Account{},
	}
	return p
}

// CreateAcquireTokenSilentParametersWithAccount creates an AcquireTokenSilentParameters instance from an account.
// This account can be pulled from the cache by calling GetAccounts
func CreateAcquireTokenSilentParametersWithAccount(scopes []string, account AccountProvider) AcquireTokenSilentParameters {
	return AcquireTokenSilentParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		account:          account,
	}
}

func (p AcquireTokenSilentParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.AuthorizationType = msalbase.AuthorizationTypeRefreshTokenExchange
	authParams.HomeaccountID = p.account.GetHomeAccountID()
}
