// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package broker

import (
	"context"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal"
)

var (
	SignInInteractively func(context.Context, AuthParams) (internal.AuthResult, error)
	SignInSilently      func(context.Context, AuthParams) (internal.AuthResult, error)
)
