// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

//CacheAccessor is an interface where the user can specify cache persistence properties.
//BeforeCacheAccess is called everytime before the cache is accessed, and AfterCacheAccess
//is called after it is accessed.
type CacheAccessor interface {
	BeforeCacheAccess(context *CacheContext)
	AfterCacheAccess(context *CacheContext)
}
