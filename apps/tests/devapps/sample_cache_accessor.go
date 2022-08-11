// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"log"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
)

type TokenCache struct {
	file string
}

func (t *TokenCache) Replace(cache cache.Unmarshaler, key string) {
	data, err := os.ReadFile(t.file)
	if err != nil {
		log.Println(err)
	}
	err = cache.Unmarshal(data)
	if err != nil {
		log.Println(err)
	}
}

func (t *TokenCache) Export(cache cache.Marshaler, key string) {
	data, err := cache.Marshal()
	if err != nil {
		log.Println(err)
	}
	err = os.WriteFile(t.file, data, 0600)
	if err != nil {
		log.Println(err)
	}
}
