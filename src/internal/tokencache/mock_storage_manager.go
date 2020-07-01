// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/stretchr/testify/mock"
)

type MockStorageManager struct {
	mock.Mock
}

func (mock *MockStorageManager) WriteAccessToken(accessToken *accessTokenCacheItem) error {
	args := mock.Called(accessToken)
	return args.Error(0)
}

func (mock *MockStorageManager) WriteRefreshToken(refreshToken *refreshTokenCacheItem) error {
	args := mock.Called(refreshToken)
	return args.Error(0)
}

func (mock *MockStorageManager) WriteIDToken(idToken *idTokenCacheItem) error {
	args := mock.Called(idToken)
	return args.Error(0)
}

func (mock *MockStorageManager) ReadAllAccounts() []*msalbase.Account {
	args := mock.Called()
	return args.Get(0).([]*msalbase.Account)
}
