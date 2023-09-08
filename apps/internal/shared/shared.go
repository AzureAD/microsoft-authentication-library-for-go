// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package shared

import (
	"net/http"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/account"
)

const (
	// CacheKeySeparator is used in creating the keys of the cache.
	CacheKeySeparator = account.CacheKeySeparator
)

type Account = account.Account

var NewAccount = account.NewAccount

// DefaultClient is our default shared HTTP client.
var DefaultClient = &http.Client{}
