// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"

type CacheContext struct {
	cache requests.ICacheManager
}

func (context *CacheContext) SerializeCache() (string, error) {
	return context.cache.Serialize()
}

func (context *CacheContext) DeserializeCache(data []byte) error {
	return context.cache.Deserialize(data)
}
