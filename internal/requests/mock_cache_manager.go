// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"context"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/stretchr/testify/mock"
)

//MockCacheManager is used in testing where the CacheManager interface is required
type MockCacheManager struct {
	mock.Mock
}

func (mock *MockCacheManager) TryReadCache(ctx context.Context, authParameters msalbase.AuthParametersInternal, webRequestManager WebRequestManager) (msalbase.StorageTokenResponse, error) {
	args := mock.Called(authParameters, webRequestManager)
	return args.Get(0).(msalbase.StorageTokenResponse), args.Error(1)
}

func (mock *MockCacheManager) CacheTokenResponse(authParameters msalbase.AuthParametersInternal, tokenResponse msalbase.TokenResponse) (msalbase.Account, error) {
	args := mock.Called(authParameters, tokenResponse)
	return args.Get(0).(msalbase.Account), args.Error(1)
}

func (mock *MockCacheManager) DeleteCachedRefreshToken(authParameters msalbase.AuthParametersInternal) error {
	args := mock.Called(authParameters)
	return args.Error(0)
}

func (mock *MockCacheManager) GetAllAccounts() ([]msalbase.Account, error) {
	args := mock.Called()
	return args.Get(0).([]msalbase.Account), args.Error(1)
}

func (mock *MockCacheManager) Serialize() (string, error) {
	args := mock.Called()
	return args.String(0), args.Error(1)
}

func (mock *MockCacheManager) Deserialize(data []byte) error {
	args := mock.Called(data)
	return args.Error(0)
}
