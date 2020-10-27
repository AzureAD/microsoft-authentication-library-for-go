// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

// AccountProvider represents an account that is returned to users.
// This can help with accessing the cache for tokens.
type AccountProvider interface {
	GetUsername() string
	GetHomeAccountID() string
	GetEnvironment() string
}
