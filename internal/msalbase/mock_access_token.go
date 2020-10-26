// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import "github.com/stretchr/testify/mock"

type MockAccessToken struct {
	mock.Mock
}

func (mock *MockAccessToken) GetSecret() string {
	args := mock.Called()
	return args.String(0)
}

func (mock *MockAccessToken) GetExpiresOn() string {
	args := mock.Called()
	return args.String(0)
}

func (mock *MockAccessToken) GetScopes() string {
	args := mock.Called()
	return args.String(0)
}
