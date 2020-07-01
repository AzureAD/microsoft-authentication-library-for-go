// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import "github.com/stretchr/testify/mock"

type MockCredential struct {
	mock.Mock
}

func (mock *MockCredential) CreateKey() string {
	args := mock.Called()
	return args.String(0)
}

func (mock *MockCredential) GetSecret() string {
	args := mock.Called()
	return args.String(0)
}
