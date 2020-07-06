// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type NetworkedCacheManager struct {
	webRequestManager   IWebRequestManager
	cacheManager        ICacheManager
	environmentMetadata *EnvironmentMetadata
	realmMetadata       IRealmMetadata
	authParameters      *msalbase.AuthParametersInternal
}
