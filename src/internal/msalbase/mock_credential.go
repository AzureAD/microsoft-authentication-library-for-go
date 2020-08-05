// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import "github.com/stretchr/testify/mock"

type mockCredential struct {
	mock.Mock
}

//CreateKey mocks the CreateKey method of a Credential
func (mock *mockCredential) CreateKey() string {
	args := mock.Called()
	return args.String(0)
}

//GetSecret mocks the GetSecret method of a Credential
func (mock *mockCredential) GetSecret() string {
	args := mock.Called()
	return args.String(0)
}
