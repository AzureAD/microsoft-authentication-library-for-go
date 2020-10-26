// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"reflect"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
)

func TestContextSerialize(t *testing.T) {
	mockCacheMgr := new(requests.MockCacheManager)
	context := &CacheContext{
		cache: mockCacheMgr,
	}
	exampleCache := "jsonCache"
	mockCacheMgr.On("Serialize").Return(exampleCache, nil)
	actualCache, err := context.SerializeCache()
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualCache, exampleCache) {
		t.Errorf("Cache should be %s but it is %s", exampleCache, actualCache)
	}
}

func TestContextDeserialize(t *testing.T) {
	mockCacheMgr := new(requests.MockCacheManager)
	context := &CacheContext{
		cache: mockCacheMgr,
	}
	exampleCache := []byte("jsonCache")
	mockCacheMgr.On("Deserialize", exampleCache).Return(nil)
	err := context.DeserializeCache(exampleCache)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}
