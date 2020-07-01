// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"github.com/stretchr/testify/mock"
)

type MockCacheManager struct {
	mock.Mock
}

func (mock *MockCacheManager) TryReadCache(authParameters *AuthParametersInternal) (*StorageTokenResponse, error) {
	args := mock.Called(authParameters)
	return args.Get(0).(*StorageTokenResponse), args.Error(1)
}

func (mock *MockCacheManager) CacheTokenResponse(authParameters *AuthParametersInternal,
	tokenResponse *TokenResponse) (*Account, error) {
	args := mock.Called(authParameters, tokenResponse)
	return args.Get(0).(*Account), args.Error(1)
}

func (mock *MockCacheManager) DeleteCachedRefreshToken(authParameters *AuthParametersInternal) error {
	args := mock.Called(authParameters)
	return args.Error(0)
}

func (mock *MockCacheManager) GetAllAccounts() []*Account {
	args := mock.Called()
	return args.Get(0).([]*Account)
}
