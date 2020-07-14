// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"reflect"
	"testing"
)

var idToken = &idTokenCacheItem{
	HomeAccountID:  "HID",
	Environment:    "env",
	CredentialType: "IdToken",
	ClientID:       "clientID",
	Realm:          "realm",
	Secret:         "id",
}

func TestCreateIDTokenCacheItem(t *testing.T) {
	actualIDToken := CreateIDTokenCacheItem("HID", "env", "realm", "clientID", "id")
	if !reflect.DeepEqual(actualIDToken, idToken) {
		t.Errorf("Actual ID token %v differs from expected ID token %v", actualIDToken, idToken)
	}
}

func TestCreateKeyForIDToken(t *testing.T) {
	expectedKey := "HID-env-IdToken-clientID-realm"
	actualKey := idToken.CreateKey()
	if !reflect.DeepEqual(actualKey, expectedKey) {
		t.Errorf("Actual key %v differs from expected key %v", actualKey, expectedKey)
	}
}

func TestIDTokenPopulateFromJSONMap(t *testing.T) {
	jsonMap := map[string]interface{}{
		"home_account_id": "hid",
		"environment":     "env",
		"extra":           "this_is_extra",
	}
	expectedIDToken := &idTokenCacheItem{
		HomeAccountID:    "hid",
		Environment:      "env",
		additionalFields: map[string]interface{}{"extra": "this_is_extra"},
	}
	actualIDToken := &idTokenCacheItem{}
	err := actualIDToken.populateFromJSONMap(jsonMap)
	if err != nil {
		t.Errorf("Error is supposed to be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualIDToken, expectedIDToken) {
		t.Errorf("Actual ID token %+v differs from expected ID token %+v", actualIDToken, expectedIDToken)
	}
}

func TestIDTokenConvertToJSONMap(t *testing.T) {
	idToken := &idTokenCacheItem{
		HomeAccountID:    "hid",
		Environment:      "env",
		additionalFields: map[string]interface{}{"extra": "this_is_extra"},
	}
	jsonMap := map[string]interface{}{
		"home_account_id": "hid",
		"environment":     "env",
		"extra":           "this_is_extra",
	}
	actualJSONMap, _ := idToken.convertToJSONMap()
	if !reflect.DeepEqual(actualJSONMap, jsonMap) {
		t.Errorf("JSON ID token %+v differs from expected JSON ID token %+v", actualJSONMap, jsonMap)
	}
}
