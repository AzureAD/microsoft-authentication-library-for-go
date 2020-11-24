// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
	"github.com/stretchr/testify/mock"
)

type mockCacheAccessor struct {
	mock.Mock
}

func (mock *mockCacheAccessor) BeforeCacheAccess(context requests.CacheManager) {
	mock.Called(context)
}

func (mock *mockCacheAccessor) AfterCacheAccess(context requests.CacheManager) {
	mock.Called(context)
}
