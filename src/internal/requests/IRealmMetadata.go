package requests

import (
	"github.com/markzuber/msalgo/internal/msalbase"
)

type IRealmMetadata interface {
	QueryCanonicalRealmFromServer(authParameters *msalbase.AuthParametersInternal) (string, error)
}
