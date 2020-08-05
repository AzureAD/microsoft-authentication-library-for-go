// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import "github.com/stretchr/testify/mock"

type mockAccessToken struct {
	mock.Mock
}

func (mock *mockAccessToken) GetSecret() string {
	args := mock.Called()
	return args.String(0)
}

func (mock *mockAccessToken) GetExpiresOn() string {
	args := mock.Called()
	return args.String(0)
}

func (mock *mockAccessToken) GetScopes() string {
	args := mock.Called()
	return args.String(0)
}
