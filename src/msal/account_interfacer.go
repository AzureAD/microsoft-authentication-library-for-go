// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

//AccountInterfacer is an interface representing an account that is returned to users.
//This can help with accessing the cache for tokens.
type AccountInterfacer interface {
	GetUsername() string
	GetHomeAccountID() string
	GetEnvironment() string
}
