// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
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
