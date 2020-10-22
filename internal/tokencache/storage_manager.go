// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

//StorageManager is an interface representing the read/write operations of the cache
type StorageManager interface {
	ReadAccessToken(
		homeAccountID string,
		envAliases []string,
		realm string,
		clientID string,
		scopes []string) *accessTokenCacheItem

	WriteAccessToken(accessToken *accessTokenCacheItem) error

	ReadRefreshToken(
		homeAccountID string,
		envAliases []string,
		familyID string,
		clientID string,
	) *refreshTokenCacheItem

	WriteRefreshToken(refreshToken *refreshTokenCacheItem) error

	ReadIDToken(
		homeAccountID string,
		envAliases []string,
		realm string,
		clientID string,
	) *idTokenCacheItem

	WriteIDToken(idToken *idTokenCacheItem) error

	ReadAllAccounts() []*msalbase.Account

	ReadAccount(homeAccountID string, envAliases []string, realm string) *msalbase.Account

	WriteAccount(account *msalbase.Account) error

	DeleteAccounts(homeAccountID string, envAliases []string) error

	ReadAppMetadata(envAliases []string, clientID string) *appMetadata

	WriteAppMetadata(appMetadata *appMetadata) error

	Serialize() (string, error)

	Deserialize(cacheData []byte) error
}
