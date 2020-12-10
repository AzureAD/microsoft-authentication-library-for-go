// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/storage"
	"github.com/stretchr/testify/mock"
)

type mockCacheAccessor struct {
	mock.Mock
}

func (mock *mockCacheAccessor) Replace(context *storage.Manager) {
	mock.Called(context)
}

func (mock *mockCacheAccessor) Export(context *storage.Manager) {
	mock.Called(context)
}
