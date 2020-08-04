// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/stretchr/testify/mock"

//MockHTTPManager is used in testing where the HTTPManager interface is required
type MockHTTPManager struct {
	mock.Mock
}

//Get mocks the Get method of a HTTPManager
func (mock *MockHTTPManager) Get(url string, requestHeaders map[string]string) (HTTPManagerResponse, error) {
	args := mock.Called(url, requestHeaders)
	return args.Get(0).(HTTPManagerResponse), args.Error(1)
}

//Post mocks the Post method of a HTTPManager
func (mock *MockHTTPManager) Post(url string, body string, requestHeaders map[string]string) (HTTPManagerResponse, error) {
	args := mock.Called(url, body, requestHeaders)
	return args.Get(0).(HTTPManagerResponse), args.Error(1)
}
