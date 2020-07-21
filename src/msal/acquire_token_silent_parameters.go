// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"reflect"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

// AcquireTokenSilentParameters stuff
type AcquireTokenSilentParameters struct {
	commonParameters *acquireTokenCommonParameters
	account          IAccount
}

func CreateAcquireTokenSilentParameters(scopes []string) *AcquireTokenSilentParameters {
	p := &AcquireTokenSilentParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
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
	if !reflect.ValueOf(p.account).IsNil() {
		authParams.HomeaccountID = ""
	} else {
		authParams.HomeaccountID = p.account.GetHomeAccountID()
	}
}
