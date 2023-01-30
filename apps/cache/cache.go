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

import "context"

// Marshaler marshals data from an internal cache to bytes that can be stored.
type Marshaler interface {
	Marshal() ([]byte, error)
}

// Unmarshaler unmarshals data from a storage medium into the internal cache, overwriting it.
type Unmarshaler interface {
	Unmarshal([]byte) error
}

// Serializer can serialize the cache to binary or from binary into the cache.
type Serializer interface {
	Marshaler
	Unmarshaler
}

// ExportReplaceCtx is the same as ExportReplace except that it supports passing a context.Context
// object. A type implementing ExportReplaceCtx must make calls to ExportReplace.Replace/Export call
// ReplaceCtx/ExportCtx with a context.Background() set to the default timeout.
// nil Context is not supported and we do not define
// the outcome of passing one. A Context without a timeout must receive a default timeout specified
// by the implementor. Retries must be implemented inside the implementation.
type ExportReplaceCtx interface {
	ExportReplace

	// ReplaceCtx replaces the cache with what is in external storage.
	// key is the suggested key which can be used for partioning the cache.
	// Implementors should honor Context cancellations and return a context.Canceled or
	// context.DeadlineExceeded in those cases.
	ReplaceCtx(ctx context.Context, cache Unmarshaler, key string) error
	// ExportCtx writes the binary representation of the cache (cache.Marshal()) to
	// external storage. This is considered opaque.
	// key is the suggested key which can be used for partioning the cache.
	// Context cancellations should be honorted as in ReplaceCtx.
	ExportCtx(ctx context.Context, cache Marshaler, key string) error
}

// ExportReplace is used to export or replace what is in the cache. It must implement a default
// timeout for both Replace and Export. Errors must be retried until the timeout.  A call to Replace
// or Export is not guaranteed to succeed. If creating a new implementation, use ExportReplaceCtx.
type ExportReplace interface {
	// Replace replaces the cache with what is in external storage.
	// key is the suggested key which can be used for partioning the cache
	Replace(cache Unmarshaler, key string)
	// Export writes the binary representation of the cache (cache.Marshal()) to
	// external storage. This is considered opaque.
	// key is the suggested key which can be used for partioning the cache
	Export(cache Marshaler, key string)
}
