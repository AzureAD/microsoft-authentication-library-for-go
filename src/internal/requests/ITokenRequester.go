// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

type ITokenRequester interface {
	Execute() (*msalbase.TokenResponse, error)
}
