// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

//AccountInterfacer is an interface returned to users that helps with accessing the cache
type AccountInterfacer interface {
	GetUsername() string
	GetHomeAccountID() string
	GetEnvironment() string
}
