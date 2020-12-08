// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"io/ioutil"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/cache"

	log "github.com/sirupsen/logrus"
)

type SampleCacheAccessor struct {
	file string
}

func (accessor *SampleCacheAccessor) IntoCache(cache cache.Unmarshaler) {
	jsonFile, err := os.Open(accessor.file)
	if err != nil {
		log.Fatal(err)
	}
	defer jsonFile.Close()
	data, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		log.Fatal(err)
	}
	err = cache.Unmarshal(data)
	if err != nil {
		log.Fatal(err)
	}
}

func (accessor *SampleCacheAccessor) ExportCache(cache cache.Marshaler) {
	data, err := cache.Marshal()
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(accessor.file, data, 0644)
	if err != nil {
		log.Fatal(err)
	}
}
