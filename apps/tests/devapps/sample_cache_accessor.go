// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"log"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
)

type TokenCache struct {
	file string

	// This will satisfy the ExportReplace and ExportReplaceCtx interfaces.
	// We do not need to implement the Replace() or Export() methods as
	// ReplaceCtx() and ExportCtx() will be chosen on each call.
	cache.ExportReplaceCtx
}

func (t *TokenCache) ReplaceCtx(ctx context.Context, cache cache.Unmarshaler, key string) {
	data, err := os.ReadFile(t.file)
	if err != nil {
		log.Println(err)
	}
	err = cache.Unmarshal(data)
	if err != nil {
		log.Println(err)
	}
}

func (t *TokenCache) ExportCtx(ctx context.Context, cache cache.Marshaler, key string) {
	data, err := cache.Marshal()
	if err != nil {
		log.Println(err)
	}
	err = os.WriteFile(t.file, data, 0600)
	if err != nil {
		log.Println(err)
	}
}
