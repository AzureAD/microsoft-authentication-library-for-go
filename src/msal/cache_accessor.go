// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

//CacheAccessor is an interface where the user can specify cache persistence properties
type CacheAccessor interface {
	BeforeCacheAccess(context *CacheContext)
	AfterCacheAccess(context *CacheContext)
}
