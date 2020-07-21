// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/stretchr/testify/mock"

type MockHTTPManager struct {
	mock.Mock
}

func (mock *MockHTTPManager) Get(url string, requestHeaders map[string]string) (IHTTPManagerResponse, error) {
	args := mock.Called(url, requestHeaders)
	return args.Get(0).(IHTTPManagerResponse), args.Error(1)
}

func (mock *MockHTTPManager) Post(url string, body string, requestHeaders map[string]string) (IHTTPManagerResponse, error) {
	args := mock.Called(url, body, requestHeaders)
	return args.Get(0).(IHTTPManagerResponse), args.Error(1)
}
