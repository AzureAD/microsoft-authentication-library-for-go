// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"io/ioutil"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/cache"

	log "github.com/sirupsen/logrus"
)

type TokenCache struct {
	file string
}

func (t *TokenCache) IntoCache(cache cache.Unmarshaler) {
	jsonFile, err := os.Open(t.file)
	if err != nil {
		log.Error(err)
	}
	defer jsonFile.Close()
	data, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		log.Error(err)
	}
	err = cache.Unmarshal(data)
	if err != nil {
		log.Error(err)
	}
}

func (t *TokenCache) ExportCache(cache cache.Marshaler) {
	data, err := cache.Marshal()
	if err != nil {
		log.Error(err)
	}
	err = ioutil.WriteFile(t.file, data, 0600)
	if err != nil {
		log.Error(err)
	}
}
