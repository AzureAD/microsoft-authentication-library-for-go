// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"reflect"
	"testing"
)

var (
	idHid        = "HID"
	idEnv        = "env"
	idCredential = "IdToken"
	idClient     = "clientID"
	idRealm      = "realm"
	idTokSecret  = "id"
)

var idToken = &idTokenCacheItem{
	HomeAccountID:  &idHid,
	Environment:    &idEnv,
	CredentialType: &idCredential,
	ClientID:       &idClient,
	Realm:          &idRealm,
	Secret:         &idTokSecret,
}

func TestCreateIDTokenCacheItem(t *testing.T) {
	actualIDToken := CreateIDTokenCacheItem("HID", "env", "realm", "clientID", "id")
	actualHomeID := *actualIDToken.HomeAccountID
	if !reflect.DeepEqual(actualHomeID, idHid) {
		t.Errorf("Actual home account id %+v differs from expected home account id %+v", actualHomeID, idHid)
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
		"home_account_id": "HID",
		"environment":     "env",
		"extra":           "this_is_extra",
	}
	actualIDToken := &idTokenCacheItem{}
	err := actualIDToken.populateFromJSONMap(jsonMap)
	if err != nil {
		t.Errorf("Error is supposed to be nil, but it is %v", err)
	}
	actualHomeID := *actualIDToken.HomeAccountID
	if !reflect.DeepEqual(actualHomeID, idHid) {
		t.Errorf("Actual home account id %+v differs from expected home account id %+v", actualHomeID, idHid)
	}
}

func TestIDTokenConvertToJSONMap(t *testing.T) {
	idToken := &idTokenCacheItem{
		HomeAccountID:    &idHid,
		Environment:      &idEnv,
		Realm:            nil,
		additionalFields: map[string]interface{}{"extra": "this_is_extra"},
	}
	jsonMap := map[string]interface{}{
		"home_account_id": "HID",
		"environment":     "env",
		"extra":           "this_is_extra",
	}
	actualJSONMap, err := idToken.convertToJSONMap()
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualJSONMap, jsonMap) {
		t.Errorf("JSON ID token %+v differs from expected JSON ID token %+v", actualJSONMap, jsonMap)
	}
}
