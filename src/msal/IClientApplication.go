// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
)

type IClientApplication interface {
	AcquireTokenSilent(*AcquireTokenSilentParameters) (IAuthenticationResult, error)
	executeTokenRequestWithoutCacheWrite(requests.ITokenRequester, *msalbase.AuthParametersInternal) (IAuthenticationResult, error)
}
