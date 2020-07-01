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
