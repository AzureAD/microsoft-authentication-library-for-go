// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

type Credential interface {
	CreateKey() string
	GetSecret() string
}
