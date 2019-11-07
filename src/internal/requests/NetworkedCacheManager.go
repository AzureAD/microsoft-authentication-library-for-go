package requests

import (
	"github.com/markzuber/msalgo/internal/msalbase"
)

type NetworkedCacheManager struct {
	webRequestManager   IWebRequestManager
	cacheManager        msalbase.ICacheManager
	environmentMetadata *EnvironmentMetadata
	realmMetadata       IRealmMetadata
	authParameters      *msalbase.AuthParametersInternal
}
