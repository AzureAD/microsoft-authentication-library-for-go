// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"internal/msalbase"
)

type NetworkedCacheManager struct {
	webRequestManager   IWebRequestManager
	cacheManager        msalbase.ICacheManager
	environmentMetadata *EnvironmentMetadata
	realmMetadata       IRealmMetadata
	authParameters      *msalbase.AuthParametersInternal
}
