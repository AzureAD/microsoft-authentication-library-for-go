// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"io/ioutil"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/storage"

	log "github.com/sirupsen/logrus"
)

type SampleCacheAccessor struct {
	file string
}

func (accessor *SampleCacheAccessor) BeforeCacheAccess(cache *storage.Manager) {
	jsonFile, err := os.Open(accessor.file)
	if err != nil {
		log.Fatal(err)
	}
	defer jsonFile.Close()
	data, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		log.Fatal(err)
	}
	err = cache.Deserialize(data)
	if err != nil {
		log.Fatal(err)
	}
}

func (accessor *SampleCacheAccessor) AfterCacheAccess(cache *storage.Manager) {
	data, err := cache.Serialize()
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(accessor.file, []byte(data), 0644)
	if err != nil {
		log.Fatal(err)
	}
}
