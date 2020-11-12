// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

// StorageManager is an interface representing the read/write operations of the cache.
type StorageManager interface {
	ReadAccessToken(homeAccountID string, envAliases []string, realm, clientID string, scopes []string) (accessTokenCacheItem, error)
	WriteAccessToken(accessToken accessTokenCacheItem) error
	ReadRefreshToken(homeAccountID string, envAliases []string, familyID, clientID string) (refreshTokenCacheItem, error)
	WriteRefreshToken(refreshToken refreshTokenCacheItem) error
	ReadIDToken(homeAccountID string, envAliases []string, realm, clientID string) (idTokenCacheItem, error)
	WriteIDToken(idToken idTokenCacheItem) error
	ReadAllAccounts() ([]msalbase.Account, error)
	ReadAccount(homeAccountID string, envAliases []string, realm string) (msalbase.Account, error)
	WriteAccount(account msalbase.Account) error
	DeleteAccounts(homeAccountID string, envAliases []string) error
	ReadAppMetadata(envAliases []string, clientID string) (appMetadata, error)
	WriteAppMetadata(appMetadata appMetadata) error
	Serialize() (string, error)
	Deserialize(cacheData []byte) error
}
