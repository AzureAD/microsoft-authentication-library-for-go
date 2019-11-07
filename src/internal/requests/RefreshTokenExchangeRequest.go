package requests

import (
	"github.com/markzuber/msalgo/internal/msalbase"
)

// RefreshTokenExchangeRequest stuff
type RefreshTokenExchangeRequest struct {
	webRequestManager IWebRequestManager
	cacheManager      msalbase.ICacheManager
	authParameters    *msalbase.AuthParametersInternal
}

// CreateRefreshTokenExchangeRequest stuff
func CreateRefreshTokenExchangeRequest(
	webRequestManager IWebRequestManager,
	cacheManager msalbase.ICacheManager,
	authParameters *msalbase.AuthParametersInternal) *RefreshTokenExchangeRequest {
	req := &RefreshTokenExchangeRequest{webRequestManager, cacheManager, authParameters}
	return req
}

// Execute stuff
func (req *RefreshTokenExchangeRequest) Execute() (*msalbase.TokenResponse, error) {

	return nil, nil
}
