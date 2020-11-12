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
	idHid        = "HID"
	idEnv        = "env"
	idCredential = "IdToken"
	idClient     = "clientID"
	idRealm      = "realm"
	idTokSecret  = "id"
)

var idToken = idTokenCacheItem{
	HomeAccountID:  idHid,
	Environment:    idEnv,
	CredentialType: idCredential,
	ClientID:       idClient,
	Realm:          idRealm,
	Secret:         idTokSecret,
}

func TestCreateKeyForIDToken(t *testing.T) {
	want := "HID-env-IdToken-clientID-realm"
	if idToken.CreateKey() != want {
		t.Errorf("actual key %v differs from expected key %v", idToken.CreateKey(), want)
	}
}

func TestIDTokenUnmarshal(t *testing.T) {
	jsonMap := map[string]interface{}{
		"home_account_id": "HID",
		"environment":     "env",
		"extra":           "this_is_extra",
	}
	b, err := stdJSON.Marshal(jsonMap)
	if err != nil {
		panic(err)
	}

	want := idTokenCacheItem{
		HomeAccountID: "HID",
		Environment:   "env",
		AdditionalFields: map[string]interface{}{
			"extra": json.MarshalRaw("this_is_extra"),
		},
	}

	got := idTokenCacheItem{}
	if err := json.Unmarshal(b, &got); err != nil {
		panic(err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestIDTokenUnmarshal: -want/+got:\n%s", diff)
	}
}

func TestIDTokenMarshal(t *testing.T) {
	idToken := idTokenCacheItem{
		HomeAccountID:    idHid,
		Environment:      idEnv,
		Realm:            "",
		AdditionalFields: map[string]interface{}{"extra": "this_is_extra"},
	}

	want := map[string]interface{}{
		"home_account_id": "HID",
		"environment":     "env",
		"extra":           "this_is_extra",
	}

	b, err := json.Marshal(idToken)
	if err != nil {
		panic(err)
	}
	got := map[string]interface{}{}

	if err := stdJSON.Unmarshal(b, &got); err != nil {
		panic(err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestIDTokenMarshal: -want/+got:\n%s", diff)
	}
}
