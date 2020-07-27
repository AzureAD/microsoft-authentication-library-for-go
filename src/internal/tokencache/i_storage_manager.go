// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type IStorageManager interface {
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

	ReadAppMetadata(envAliases []string, clientID string) *AppMetadata

	WriteAppMetadata(appMetadata *AppMetadata) error

	Serialize() (string, error)

	Deserialize(cacheData []byte) error
}
