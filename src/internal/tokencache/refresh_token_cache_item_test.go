// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"reflect"
	"testing"
)

var rt = &refreshTokenCacheItem{
	HomeAccountID:  "HID",
	Environment:    "env",
	ClientID:       "clientID",
	CredentialType: "RefreshToken",
	Secret:         "secret",
}

func TestCreateRefreshTokenCacheItem(t *testing.T) {
	actualRT := CreateRefreshTokenCacheItem("HID", "env", "clientID", "secret", "")
	if !reflect.DeepEqual(actualRT, rt) {
		t.Errorf("Actual refresh token %v differs from expected refresh token %v", actualRT, rt)
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
		"secret":          "100",
	}
	expectedRefreshToken := &refreshTokenCacheItem{
		HomeAccountID:    "hid",
		Environment:      "env",
		Secret:           "100",
		additionalFields: map[string]interface{}{"extra": "this_is_extra"},
	}
	actualRefreshToken := &refreshTokenCacheItem{}
	err := actualRefreshToken.populateFromJSONMap(jsonMap)
	if err != nil {
		t.Errorf("Error is supposed to be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualRefreshToken, expectedRefreshToken) {
		t.Errorf("Actual refresh token %+v differs from expected refresh token %+v", actualRefreshToken, expectedRefreshToken)
	}
}

func TestRefreshTokenConvertToJSONMap(t *testing.T) {
	refreshToken := &refreshTokenCacheItem{
		HomeAccountID:    "hid",
		Environment:      "env",
		CredentialType:   "RefreshToken",
		Secret:           "100",
		additionalFields: map[string]interface{}{"extra": "this_is_extra"},
	}
	jsonMap := map[string]interface{}{
		"home_account_id": "hid",
		"environment":     "env",
		"credential_type": "RefreshToken",
		"secret":          "100",
		"extra":           "this_is_extra",
	}
	actualJSONMap, _ := refreshToken.convertToJSONMap()
	if !reflect.DeepEqual(jsonMap, actualJSONMap) {
		t.Errorf("JSON refresh token %+v differs from expected JSON refresh token %+v", actualJSONMap, jsonMap)
	}
}
