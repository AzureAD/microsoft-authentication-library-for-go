// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"

	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src/msal"
)

type SampleCacheAccessor struct {
	file string
}

func (accessor *SampleCacheAccessor) BeforeCacheAccess(context *msalgo.CacheContext) {
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

func (accessor *SampleCacheAccessor) AfterCacheAccess(context *msalgo.CacheContext) {
	data, err := context.SerializeCache()
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(accessor.file, []byte(data), 0644)
	if err != nil {
		log.Fatal(err)
	}
}
