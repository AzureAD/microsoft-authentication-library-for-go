// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

// CacheAccessor represents the events that can be handled on cache access.
// BeforeCacheAccess is called everytime before the cache is accessed, and AfterCacheAccess
// is called after it is accessed.
type CacheAccessor interface {
	BeforeCacheAccess(context *CacheContext)
	AfterCacheAccess(context *CacheContext)
}
