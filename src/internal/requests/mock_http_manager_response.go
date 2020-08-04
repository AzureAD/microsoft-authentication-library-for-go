// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import "github.com/stretchr/testify/mock"

type MockHTTPManagerResponse struct {
	mock.Mock
}

func (mock *MockHTTPManagerResponse) GetResponseCode() int {
	args := mock.Called()
	return args.Int(0)
}
