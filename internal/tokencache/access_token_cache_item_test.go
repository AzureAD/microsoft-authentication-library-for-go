// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"reflect"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
)

var (
	testHID       = "testHID"
	env           = "env"
	credential    = "AccessToken"
	clientID      = "clientID"
	realm         = "realm"
	scopes        = "user.read"
	secret        = "access"
	expiresOn     = "1592049600"
	extExpiresOn  = "1592049600"
	cachedAt      = "1592049600"
	atCacheEntity = &accessTokenCacheItem{
		HomeAccountID:                  testHID,
		Environment:                    env,
		CredentialType:                 credential,
		ClientID:                       clientID,
		Realm:                          realm,
		Scopes:                         scopes,
		Secret:                         secret,
		ExpiresOnUnixTimestamp:         expiresOn,
		ExtendedExpiresOnUnixTimestamp: extExpiresOn,
		CachedAt:                       cachedAt,
	}
)

func TestCreateAccessTokenCacheItem(t *testing.T) {
	testExpiresOn := time.Date(2020, time.June, 13, 12, 0, 0, 0, time.UTC)
	testExtExpiresOn := time.Date(2020, time.June, 13, 12, 0, 0, 0, time.UTC)
	testCachedAt := time.Date(2020, time.June, 13, 11, 0, 0, 0, time.UTC)
	actualAt := createAccessTokenCacheItem("testHID",
		"env",
		"realm",
		"clientID",
		testCachedAt.Unix(),
		testExpiresOn.Unix(),
		testExtExpiresOn.Unix(),
		"user.read",
		"access",
	)
	if !reflect.DeepEqual(extExpiresOn, actualAt.ExtendedExpiresOnUnixTimestamp) {
		t.Errorf("Actual ext expires on %s differs from expected ext expires on %s", actualAt.ExtendedExpiresOnUnixTimestamp, extExpiresOn)
	}
}

func TestCreateKeyForAccessToken(t *testing.T) {
	expectedKey := "testHID-env-AccessToken-clientID-realm-user.read"
	actualKey := atCacheEntity.CreateKey()
	if !reflect.DeepEqual(actualKey, expectedKey) {
		t.Errorf("Actual key %v differs from expected key %v", actualKey, expectedKey)
	}
}

func TestAccessTokenPopulateFromJSONMap(t *testing.T) {
	jsonMap := map[string]interface{}{
		"home_account_id": "testHID",
		"environment":     "env",
		"extra":           "this_is_extra",
		"cached_at":       "100",
	}
	testCachedAt := "100"
	want := &accessTokenCacheItem{
		HomeAccountID:    testHID,
		Environment:      env,
		CachedAt:         testCachedAt,
		additionalFields: map[string]interface{}{"extra": "this_is_extra"},
	}
	got := &accessTokenCacheItem{}
	err := got.populateFromJSONMap(jsonMap)
	if err != nil {
		t.Errorf("Error is supposed to be nil, but it is %v", err)
	}
	if diff := (&pretty.Config{IncludeUnexported: false}).Compare(want, got); diff != "" {
		t.Errorf("TestAccessTokenPopulateFromJSONMap(access tokens): -want/+got:\n %s", diff)
	}

	gotExtra := got.additionalFields["extra"].(string)
	if gotExtra != "this_is_extra" {
		t.Errorf("TestAccessTokenPopulateFromJSONMap(extra field): got %s, want %s", gotExtra, "this_is_extra")
	}
}

func TestAccessTokenConvertToJSONMap(t *testing.T) {
	testCachedAt := "100"
	accessToken := &accessTokenCacheItem{
		HomeAccountID:    testHID,
		Environment:      "",
		CachedAt:         testCachedAt,
		CredentialType:   credential,
		additionalFields: map[string]interface{}{"extra": "this_is_extra"},
	}
	jsonMap := map[string]interface{}{
		"home_account_id": "testHID",
		"extra":           "this_is_extra",
		"cached_at":       "100",
		"credential_type": "AccessToken",
	}
	actualJSONMap, err := accessToken.convertToJSONMap()
	if err != nil {
		t.Errorf("Error should be nil; instead it is %v", err)
	}
	if !reflect.DeepEqual(jsonMap, actualJSONMap) {
		t.Errorf("JSON access token %+v differs from expected JSON access token %+v", actualJSONMap, jsonMap)
	}
}
