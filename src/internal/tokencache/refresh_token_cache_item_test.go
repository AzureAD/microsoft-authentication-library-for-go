// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"reflect"
	"testing"
)

var hid = "HID"
var rtEnv = "env"
var rtClientID = "clientID"
var rtCredential = "RefreshToken"
var refSecret = "secret"

var rt = &refreshTokenCacheItem{
	HomeAccountID:  &hid,
	Environment:    &env,
	ClientID:       &rtClientID,
	CredentialType: &rtCredential,
	Secret:         &refSecret,
}

func TestCreateRefreshTokenCacheItem(t *testing.T) {
	actualRT := CreateRefreshTokenCacheItem("HID", "env", "clientID", "secret", "")
	actualSecret := *actualRT.Secret
	if !reflect.DeepEqual(actualSecret, refSecret) {
		t.Errorf("Expected secret %s differs from actualSecret %s", actualSecret, refSecret)
	}
}

func TestCreateKeyForRefreshToken(t *testing.T) {
	expectedKey := "HID-env-RefreshToken-clientID"
	actualKey := rt.CreateKey()
	if !reflect.DeepEqual(expectedKey, actualKey) {
		t.Errorf("Actual key %v differs from expected key %v", actualKey, expectedKey)
	}
}

func TestRefreshTokenPopulateFromJSONMap(t *testing.T) {
	jsonMap := map[string]interface{}{
		"home_account_id": "hid",
		"environment":     "env",
		"extra":           "this_is_extra",
		"secret":          "secret",
	}
	actualRefreshToken := &refreshTokenCacheItem{}
	err := actualRefreshToken.populateFromJSONMap(jsonMap)
	if err != nil {
		t.Errorf("Error is supposed to be nil, but it is %v", err)
	}
	actualSecret := *actualRefreshToken.Secret
	if !reflect.DeepEqual(actualSecret, refSecret) {
		t.Errorf("Expected secret %s differs from actualSecret %s", actualSecret, refSecret)
	}
}

func TestRefreshTokenConvertToJSONMap(t *testing.T) {
	refreshToken := &refreshTokenCacheItem{
		HomeAccountID:    nil,
		Environment:      &rtEnv,
		CredentialType:   &rtCredential,
		Secret:           &refSecret,
		additionalFields: map[string]interface{}{"extra": "this_is_extra"},
	}
	jsonMap := map[string]interface{}{
		"environment":     "env",
		"credential_type": "RefreshToken",
		"secret":          "secret",
		"extra":           "this_is_extra",
	}
	actualJSONMap, err := refreshToken.convertToJSONMap()
	if err != nil {
		t.Errorf("Error should be nil, instead it is %v", err)
	}
	if !reflect.DeepEqual(jsonMap, actualJSONMap) {
		t.Errorf("JSON refresh token %+v differs from expected JSON refresh token %+v", actualJSONMap, jsonMap)
	}
}
