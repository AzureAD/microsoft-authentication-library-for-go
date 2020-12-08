// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import "github.com/stretchr/testify/mock"

type MockCredential struct {
	mock.Mock
}

// Key mocks the Key method of a Credential.
func (mock *MockCredential) Key() string {
	args := mock.Called()
	return args.String(0)
}

// GetSecret mocks the GetSecret method of a Credential.
func (mock *MockCredential) GetSecret() string {
	args := mock.Called()
	return args.String(0)
}
