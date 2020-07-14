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
	/*
		DeleteAccessToken(
			homeAccountID string,
			envAliases []string,
			realm string,
			clientID string,
			scopes []string) error*/

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

	/*
		DeleteAccount(
			homeAccountID string,
			environment string,
			realm string) error

		DeleteAccounts(correlationID string, homeAccountID string, environment string) (*OperationStatus, error)*/

	ReadAppMetadata(envAliases []string, clientID string) *AppMetadata
	WriteAppMetadata(appMetadata *AppMetadata) error
	//Serialize() (string, error)
}
