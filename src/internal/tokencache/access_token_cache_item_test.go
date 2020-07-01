// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"reflect"
	"testing"
	"time"
)

var atCacheEntity = &accessTokenCacheItem{
	HomeAccountID:                  "testHID",
	Environment:                    "env",
	CredentialType:                 "AccessToken",
	ClientID:                       "clientID",
	Realm:                          "realm",
	Scopes:                         "user.read",
	Secret:                         "access",
	ExpiresOnUnixTimestamp:         "1592049600",
	ExtendedExpiresOnUnixTimestamp: "1592049600",
	CachedAt:                       "1592046000",
}

func TestCreateAccessTokenCacheItem(t *testing.T) {
	expiresOn := time.Date(2020, time.June, 13, 12, 0, 0, 0, time.UTC)
	extExpiresOn := time.Date(2020, time.June, 13, 12, 0, 0, 0, time.UTC)
	cachedAt := time.Date(2020, time.June, 13, 11, 0, 0, 0, time.UTC)
	actualAt := CreateAccessTokenCacheItem("testHID",
		"env",
		"realm",
		"clientID",
		cachedAt.Unix(),
		expiresOn.Unix(),
		extExpiresOn.Unix(),
		"user.read",
		"access",
	)
	if !reflect.DeepEqual(actualAt, atCacheEntity) {
		t.Errorf("Actual access token %v differs from expected access token %v", actualAt.CachedAt, atCacheEntity)
	}
}

func TestCreateKeyForAccessToken(t *testing.T) {
	expectedKey := "testHID-env-AccessToken-clientID-realm-user.read"
	actualKey := atCacheEntity.CreateKey()
	if !reflect.DeepEqual(actualKey, expectedKey) {
		t.Errorf("Actual key %v differs from expected key %v", actualKey, expectedKey)
	}
}
