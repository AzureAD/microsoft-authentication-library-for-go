// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	stdJSON "encoding/json"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/json"
	"github.com/kylelemons/godebug/pretty"
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

func TestRefreshTokenUnmarshal(t *testing.T) {
	jsonMap := map[string]interface{}{
		"home_account_id": "hid",
		"environment":     "env",
		"extra":           "this_is_extra",
		"secret":          "secret",
	}
	b, err := stdJSON.Marshal(jsonMap)
	if err != nil {
		panic(err)
	}
	want := refreshTokenCacheItem{
		HomeAccountID: "hid",
		Environment:   "env",
		Secret:        "secret",
		AdditionalFields: map[string]interface{}{
			"extra": json.MarshalRaw("this_is_extra"),
		},
	}

	got := refreshTokenCacheItem{}
	err = json.Unmarshal(b, &got)
	if err != nil {
		panic(err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestRefreshTokenUnmarshal: -want/+got:\n%s", diff)
	}
}

func TestRefreshTokenMarshal(t *testing.T) {
	refreshToken := refreshTokenCacheItem{
		HomeAccountID:  "",
		Environment:    rtEnv,
		CredentialType: rtCredential,
		Secret:         refSecret,
		AdditionalFields: map[string]interface{}{
			"extra": "this_is_extra",
		},
	}
	want := map[string]interface{}{
		"environment":     "env",
		"credential_type": "RefreshToken",
		"secret":          "secret",
		"extra":           "this_is_extra",
	}
	b, err := json.Marshal(refreshToken)
	if err != nil {
		panic(err)
	}
	got := map[string]interface{}{}

	if err := stdJSON.Unmarshal(b, &got); err != nil {
		panic(err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestRefreshTokenMarshal: -want/+got:\n%s", diff)
	}
}
