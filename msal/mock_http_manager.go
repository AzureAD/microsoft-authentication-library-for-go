// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"net/http"

	"github.com/stretchr/testify/mock"
)

type mockHTTPManager struct {
	mock.Mock
}

func (m *mockHTTPManager) Do(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	return args.Get(0).(*http.Response), args.Error(1)
}
