// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
)

// CacheAccessor is an interface where the user can specify cache persistence properties.
// BeforeCacheAccess is called everytime before the cache is accessed, and AfterCacheAccess
// is called after it is accessed.
type CacheAccessor interface {
	BeforeCacheAccess(cache requests.CacheManager)
	AfterCacheAccess(cache requests.CacheManager)
}
