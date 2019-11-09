// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import "internal/msalbase"

type ITokenRequester interface {
	Execute() (*msalbase.TokenResponse, error)
}
