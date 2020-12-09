// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/*
Package cache allows third parties to implement external storage for caching token data
for distributed systems or multiple local applications access.

The data stored and extracted will represent the entire cache. Therefore it is recommended
one msal instance per user. This data is considered opaque and there are no guarantees to
implementers on the format being passed.
*/
package cache

// Marshaler marshals data from an internal cache to bytes that can be stored.
type Marshaler interface {
	Marshal() ([]byte, error)
}

// Unmarshaler unmarshals data from a storage medium into the internal cache, overwriting it.
type Unmarshaler interface {
	Unmarshal([]byte) error
}

// Serializer can seralize the cache to binary or from binary into the cache.
type Serializer interface {
	Marshaler
	Unmarshaler
}

// Token is used to provide external storage of token data. The data being passed is considered
// opaque.
type Token interface {
	// IntoCache reads the cache in external storage into the internal cache, replacing it.
	IntoCache(cache Unmarshaler)
	// ExportCache writes the binary representation of the cache (cache.Marshal()) to
	// external storage.
	ExportCache(cache Marshaler)
}
