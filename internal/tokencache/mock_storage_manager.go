// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/stretchr/testify/mock"
)

type MockStorageManager struct {
	mock.Mock
}

func (mock *MockStorageManager) ReadAccessToken(
	homeAccountID string,
	envAliases []string,
	realm string,
	clientID string,
	scopes []string) *accessTokenCacheItem {
	args := mock.Called(homeAccountID, envAliases, realm, clientID, scopes)
	return args.Get(0).(*accessTokenCacheItem)
}

func (mock *MockStorageManager) WriteAccessToken(accessToken *accessTokenCacheItem) error {
	args := mock.Called(accessToken)
	return args.Error(0)
}

func (mock *MockStorageManager) ReadRefreshToken(
	homeAccountID string,
	envAliases []string,
	familyID string,
	clientID string,
) *refreshTokenCacheItem {
	args := mock.Called(homeAccountID, envAliases, familyID, clientID)
	return args.Get(0).(*refreshTokenCacheItem)
}

func (mock *MockStorageManager) WriteRefreshToken(refreshToken *refreshTokenCacheItem) error {
	args := mock.Called(refreshToken)
	return args.Error(0)
}

func (mock *MockStorageManager) ReadIDToken(
	homeAccountID string,
	envAliases []string,
	realm string,
	clientID string,
) *idTokenCacheItem {
	args := mock.Called(homeAccountID, envAliases, realm, clientID)
	return args.Get(0).(*idTokenCacheItem)
}

func (mock *MockStorageManager) WriteIDToken(idToken *idTokenCacheItem) error {
	args := mock.Called(idToken)
	return args.Error(0)
}

func (mock *MockStorageManager) ReadAllAccounts() []*msalbase.Account {
	args := mock.Called()
	return args.Get(0).([]*msalbase.Account)
}

func (mock *MockStorageManager) ReadAccount(homeAccountID string, envAliases []string, realm string) *msalbase.Account {
	args := mock.Called(homeAccountID, envAliases, realm)
	return args.Get(0).(*msalbase.Account)
}

func (mock *MockStorageManager) WriteAccount(account *msalbase.Account) error {
	args := mock.Called(account)
	return args.Error(0)
}

func (mock *MockStorageManager) DeleteAccounts(homeAccountID string, envAliases []string) error {
	args := mock.Called(homeAccountID, envAliases)
	return args.Error(0)
}

func (mock *MockStorageManager) ReadAppMetadata(envAliases []string, clientID string) *appMetadata {
	args := mock.Called(envAliases, clientID)
	return args.Get(0).(*appMetadata)
}

func (mock *MockStorageManager) WriteAppMetadata(appMetadata *appMetadata) error {
	args := mock.Called(appMetadata)
	return args.Error(0)
}

func (mock *MockStorageManager) Serialize() (string, error) {
	args := mock.Called()
	return args.String(0), args.Error(1)
}

func (mock *MockStorageManager) Deserialize(cacheData []byte) error {
	args := mock.Called(cacheData)
	return args.Error(0)
}
