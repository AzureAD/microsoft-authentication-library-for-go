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
	// reflect.DeepEqual() is used under-the-hood and will always return false when
	// comparing non-nil funcs.  set this to nil to work around this behavior.
	req.GetBody = nil
	args := m.Called(req)
	return args.Get(0).(*http.Response), args.Error(1)
}
