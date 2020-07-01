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
	CredentialType: "IDToken",
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
	expectedKey := "HID-env-IDToken-clientID-realm"
	actualKey := idToken.CreateKey()
	if !reflect.DeepEqual(actualKey, expectedKey) {
		t.Errorf("Actual key %v differs from expected key %v", actualKey, expectedKey)
	}
}
