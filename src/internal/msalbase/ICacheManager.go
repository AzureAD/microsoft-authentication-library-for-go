// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

type ICacheManager interface {
	TryReadCache(authParameters *AuthParametersInternal) (*StorageTokenResponse, error)
	CacheTokenResponse(authParameters *AuthParametersInternal, tokenResponse *TokenResponse) (*Account, error)
	DeleteCachedRefreshToken(authParameters *AuthParametersInternal) error
}
