// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

//Credential is an interface for cache entries such as access, refresh and ID tokens
type Credential interface {
	CreateKey() string
	GetSecret() string
}
