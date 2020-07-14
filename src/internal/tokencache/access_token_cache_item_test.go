// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"reflect"
	"testing"
)

var testHID = "testHID"
var env = "env"
var credential = "AccessToken"
var clientID = "clientID"
var realm = "realm"
var scopes = "user.read"
var secret = "access"
var expiresOn = "1592049600"
var extExpiresOn = "1592049600"
var cachedAt = "1592049600"

var atCacheEntity = &accessTokenCacheItem{
	HomeAccountID:                  &testHID,
	Environment:                    &env,
	CredentialType:                 &credential,
	ClientID:                       &clientID,
	Realm:                          &realm,
	Scopes:                         &scopes,
	Secret:                         &secret,
	ExpiresOnUnixTimestamp:         &expiresOn,
	ExtendedExpiresOnUnixTimestamp: &extExpiresOn,
	CachedAt:                       &cachedAt,
}

/*
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
}*/

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
	expectedAccessToken := &accessTokenCacheItem{
		HomeAccountID:    &testHID,
		Environment:      &env,
		CachedAt:         &testCachedAt,
		additionalFields: map[string]interface{}{"extra": "this_is_extra"},
	}
	actualAccessToken := &accessTokenCacheItem{}
	err := actualAccessToken.populateFromJSONMap(jsonMap)
	if err != nil {
		t.Errorf("Error is supposed to be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualAccessToken, expectedAccessToken) {
		t.Errorf("Actual access token %+v differs from expected access token %+v", actualAccessToken, expectedAccessToken)
	}
	actualHID := *actualAccessToken.HomeAccountID
	if !reflect.DeepEqual(actualHID, testHID) {
		t.Errorf("Expected home account ID %s differs from actual home account ID %s", actualHID, testHID)
	}
}

func TestAccessTokenConvertToJSONMap(t *testing.T) {
	testCachedAt := "100"
	accessToken := &accessTokenCacheItem{
		HomeAccountID:    &testHID,
		Environment:      nil,
		CachedAt:         &testCachedAt,
		CredentialType:   &credential,
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
