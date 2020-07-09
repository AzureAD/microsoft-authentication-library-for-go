// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/stretchr/testify/mock"
)

type MockCacheManager struct {
	mock.Mock
}

func (mock *MockCacheManager) TryReadCache(authParameters *msalbase.AuthParametersInternal,
	webRequestManager IWebRequestManager) (*msalbase.StorageTokenResponse, error) {
	args := mock.Called(authParameters, webRequestManager)
	return args.Get(0).(*msalbase.StorageTokenResponse), args.Error(1)
}

func (mock *MockCacheManager) CacheTokenResponse(authParameters *msalbase.AuthParametersInternal,
	tokenResponse *msalbase.TokenResponse) (*msalbase.Account, error) {
	args := mock.Called(authParameters, tokenResponse)
	return args.Get(0).(*msalbase.Account), args.Error(1)
}

func (mock *MockCacheManager) DeleteCachedRefreshToken(authParameters *msalbase.AuthParametersInternal) error {
	args := mock.Called(authParameters)
	return args.Error(0)
}

func (mock *MockCacheManager) GetAllAccounts() []*msalbase.Account {
	args := mock.Called()
	return args.Get(0).([]*msalbase.Account)
}
