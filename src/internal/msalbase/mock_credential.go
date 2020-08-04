// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import "github.com/stretchr/testify/mock"

//MockCredential is used in testing where the Credential interface is required
type MockCredential struct {
	mock.Mock
}

//CreateKey mocks the CreateKey method of a Credential
func (mock *MockCredential) CreateKey() string {
	args := mock.Called()
	return args.String(0)
}

//GetSecret mocks the GetSecret method of a Credential
func (mock *MockCredential) GetSecret() string {
	args := mock.Called()
	return args.String(0)
}
