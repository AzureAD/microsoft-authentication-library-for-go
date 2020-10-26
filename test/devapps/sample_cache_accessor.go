// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal"
)

type SampleCacheAccessor struct {
	file string
}

func (accessor *SampleCacheAccessor) BeforeCacheAccess(context *msal.CacheContext) {
	jsonFile, err := os.Open(accessor.file)
	if err != nil {
		log.Fatal(err)
	}
	defer jsonFile.Close()
	data, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		log.Fatal(err)
	}
	err = context.DeserializeCache(data)
	if err != nil {
		log.Fatal(err)
	}
}

func (accessor *SampleCacheAccessor) AfterCacheAccess(context *msal.CacheContext) {
	data, err := context.SerializeCache()
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(accessor.file, []byte(data), 0644)
	if err != nil {
		log.Fatal(err)
	}
}
