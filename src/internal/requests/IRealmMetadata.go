// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"internal/msalbase"
)

type IRealmMetadata interface {
	QueryCanonicalRealmFromServer(authParameters *msalbase.AuthParametersInternal) (string, error)
}
