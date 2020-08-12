// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"

// CacheContext allows the user access to the cache to use in their CacheAccessor implementation.
type CacheContext struct {
	cache requests.CacheManager
}

// SerializeCache serializes the cache to a json string.
func (context *CacheContext) SerializeCache() (string, error) {
	return context.cache.Serialize()
}

// DeserializeCache converts a byte array representing the JSON cache to the internal cache representation.
func (context *CacheContext) DeserializeCache(data []byte) error {
	return context.cache.Deserialize(data)
}
