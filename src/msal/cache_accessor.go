// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

type CacheAccessor interface {
	BeforeCacheAccess(context *CacheContext)
	AfterCacheAccess(context *CacheContext)
}
