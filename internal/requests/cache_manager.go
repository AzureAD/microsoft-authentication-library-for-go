// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import "github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"

//CacheManager is the interface for the handling of caching operations
type CacheManager interface {
	TryReadCache(authParameters msalbase.AuthParametersInternal, webRequestManager WebRequestManager) (msalbase.StorageTokenResponse, error)
	CacheTokenResponse(authParameters msalbase.AuthParametersInternal, tokenResponse msalbase.TokenResponse) (msalbase.Account, error)
	DeleteCachedRefreshToken(authParameters msalbase.AuthParametersInternal) error
	GetAllAccounts() ([]msalbase.Account, error)
	Serialize() (string, error)
	Deserialize(data []byte) error
}
