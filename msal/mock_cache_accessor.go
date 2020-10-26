// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import "github.com/stretchr/testify/mock"

type mockCacheAccessor struct {
	mock.Mock
}

func (mock *mockCacheAccessor) BeforeCacheAccess(context *CacheContext) {
	mock.Called(context)
}

func (mock *mockCacheAccessor) AfterCacheAccess(context *CacheContext) {
	mock.Called(context)
}
