// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"reflect"
	"testing"
)

var (
	hid          = "HID"
	rtEnv        = "env"
	rtClientID   = "clientID"
	rtCredential = "RefreshToken"
	refSecret    = "secret"
)

var rt = &refreshTokenCacheItem{
	HomeAccountID:  hid,
	Environment:    env,
	ClientID:       rtClientID,
	CredentialType: rtCredential,
	Secret:         refSecret,
}

func TestCreateRefreshTokenCacheItem(t *testing.T) {
	got := createRefreshTokenCacheItem("HID", "env", "clientID", "secret", "")
	if refSecret != got.Secret {
		t.Errorf("expected secret %s differs from actualSecret %s", refSecret, got.Secret)
	}
}

func TestCreateKeyForRefreshToken(t *testing.T) {
	want := "HID-env-RefreshToken-clientID"
	got := rt.CreateKey()
	if want != got {
		t.Errorf("Actual key %v differs from expected key %v", got, want)
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

	if actualRefreshToken.Secret != refSecret {
		t.Errorf("Expected secret %s differs from actualSecret %s", actualRefreshToken.Secret, refSecret)
	}
}

func TestRefreshTokenConvertToJSONMap(t *testing.T) {
	refreshToken := &refreshTokenCacheItem{
		HomeAccountID:    "",
		Environment:      rtEnv,
		CredentialType:   rtCredential,
		Secret:           refSecret,
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
