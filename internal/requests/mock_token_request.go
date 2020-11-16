// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/stretchr/testify/mock"
)

type MockTokenRequest struct {
	mock.Mock
}

func (mock *MockTokenRequest) Execute() (msalbase.TokenResponse, error) {
	args := mock.Called()
	return args.Get(0).(msalbase.TokenResponse), args.Error(1)
}
