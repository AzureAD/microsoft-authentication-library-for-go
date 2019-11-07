package requests

import (
	"github.com/markzuber/msalgo/internal/msalbase"
)

// InteractiveRequest stuff
type InteractiveRequest struct {
	webRequestManager IWebRequestManager
	cacheManager      msalbase.ICacheManager
	authParameters    *msalbase.AuthParametersInternal
}

// CreateInteractiveRequest stuff
func CreateInteractiveRequest(
	webRequestManager IWebRequestManager,
	cacheManager msalbase.ICacheManager,
	authParameters *msalbase.AuthParametersInternal) *InteractiveRequest {
	req := &InteractiveRequest{webRequestManager, cacheManager, authParameters}
	return req
}

// Execute stuff
func (req *InteractiveRequest) Execute() (*msalbase.TokenResponse, error) {

	return nil, nil
}
