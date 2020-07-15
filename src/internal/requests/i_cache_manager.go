// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

type ICacheManager interface {
	TryReadCache(authParameters *msalbase.AuthParametersInternal, webRequestManager IWebRequestManager) (*msalbase.StorageTokenResponse, error)
	CacheTokenResponse(authParameters *msalbase.AuthParametersInternal, tokenResponse *msalbase.TokenResponse) (*msalbase.Account, error)
	DeleteCachedRefreshToken(authParameters *msalbase.AuthParametersInternal) error
	GetAllAccounts() []*msalbase.Account
	Serialize() (string, error)
	Deserialize(data []byte) error
}
