// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package internal

import (
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/account"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/tokens"
)

type AuthResult struct {
	Account        account.Account
	IDToken        tokens.IDToken
	AccessToken    string
	ExpiresOn      time.Time
	GrantedScopes  []string
	DeclinedScopes []string
}
