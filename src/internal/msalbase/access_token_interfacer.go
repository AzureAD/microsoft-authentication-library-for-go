// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

type accessTokenInterfacer interface {
	GetSecret() string
	GetExpiresOn() string
	GetScopes() string
}
