// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// TODO(jdoak): Remove testify/mock. mock libraries are usually pretty terrible in Go
// and as Rob Pike said once, he only ever used a mock one time in his career.
// In addition, mocks in all languages tend to be rigid and consistently break tests
// with minor changes (like a new call to a method) that should not have a negative effect.
// This leads to deep debugging of mock frameworks and tests. This one is not as bad as some,
// but it obscures where problems are on type changes, for example.
// Most uses I see here could be replaced with a storage manager that uses disk or memory
// This would mean that we would be testing against something real and non-fragile.

package tokencache

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/stretchr/testify/mock"
)

type MockStorageManager struct {
	mock.Mock
}

func (mock *MockStorageManager) ReadAccessToken(homeAccountID string, envAliases []string, realm, clientID string, scopes []string) (accessTokenCacheItem, error) {
	args := mock.Called(homeAccountID, envAliases, realm, clientID, scopes)
	return args.Get(0).(accessTokenCacheItem), args.Error(1)
}

func (mock *MockStorageManager) WriteAccessToken(accessToken accessTokenCacheItem) error {
	args := mock.Called(accessToken)
	return args.Error(0)
}

func (mock *MockStorageManager) ReadRefreshToken(homeAccountID string, envAliases []string, familyID, clientID string) (refreshTokenCacheItem, error) {
	args := mock.Called(homeAccountID, envAliases, familyID, clientID)
	return args.Get(0).(refreshTokenCacheItem), args.Error(1)
}

func (mock *MockStorageManager) WriteRefreshToken(refreshToken refreshTokenCacheItem) error {
	args := mock.Called(refreshToken)
	return args.Error(0)
}

func (mock *MockStorageManager) ReadIDToken(homeAccountID string, envAliases []string, realm, clientID string) (idTokenCacheItem, error) {
	args := mock.Called(homeAccountID, envAliases, realm, clientID)
	return args.Get(0).(idTokenCacheItem), args.Error(1)
}

func (mock *MockStorageManager) WriteIDToken(idToken idTokenCacheItem) error {
	args := mock.Called(idToken)
	return args.Error(0)
}

func (mock *MockStorageManager) ReadAllAccounts() ([]msalbase.Account, error) {
	args := mock.Called()
	return args.Get(0).([]msalbase.Account), args.Error(1)
}

func (mock *MockStorageManager) ReadAccount(homeAccountID string, envAliases []string, realm string) (msalbase.Account, error) {
	args := mock.Called(homeAccountID, envAliases, realm)
	return args.Get(0).(msalbase.Account), args.Error(1)
}

func (mock *MockStorageManager) WriteAccount(account msalbase.Account) error {
	args := mock.Called(account)
	return args.Error(0)
}

func (mock *MockStorageManager) DeleteAccounts(homeAccountID string, envAliases []string) error {
	args := mock.Called(homeAccountID, envAliases)
	return args.Error(0)
}

func (mock *MockStorageManager) ReadAppMetadata(envAliases []string, clientID string) (appMetadata, error) {
	args := mock.Called(envAliases, clientID)
	return args.Get(0).(appMetadata), args.Error(1)
}

func (mock *MockStorageManager) WriteAppMetadata(appMetadata appMetadata) error {
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
