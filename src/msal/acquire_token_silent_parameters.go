// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
)

// AcquireTokenSilentParameters stuff
type AcquireTokenSilentParameters struct {
	commonParameters *acquireTokenCommonParameters
	account          IAccount
	requestType      requests.RefreshTokenReqType
	clientCredential *msalbase.ClientCredential
}

func CreateAcquireTokenSilentParameters(scopes []string) *AcquireTokenSilentParameters {
	p := &AcquireTokenSilentParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		account:          &msalbase.Account{},
	}
	return p
}

// CreateAcquireTokenSilentParameters stuff
func CreateAcquireTokenSilentParametersWithAccount(scopes []string, account IAccount) *AcquireTokenSilentParameters {
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
