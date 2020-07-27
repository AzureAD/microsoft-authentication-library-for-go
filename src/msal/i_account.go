// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

type IAccount interface {
	GetUsername() string
	GetHomeAccountID() string
	GetEnvironment() string
}
