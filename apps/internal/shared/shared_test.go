// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package shared

import (
	stdJSON "encoding/json"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json"

	"github.com/kylelemons/godebug/pretty"
)

var (
	accHID   = "hid"
	accEnv   = "env"
	accRealm = "realm"
	authType = "MSSTS"
	accLid   = "lid"
	accUser  = "user"
)

func TestAccountUnmarshal(t *testing.T) {
	jsonMap := map[string]interface{}{
		"home_account_id": "hid",
		"environment":     "env",
		"extra":           "this_is_extra",
		"authority_type":  authType,
	}

	b, err := stdJSON.Marshal(jsonMap)
	if err != nil {
		panic(err)
	}

	want := Account{
		HomeAccountID: accHID,
		Environment:   accEnv,
		AuthorityType: authType,
		AdditionalFields: map[string]interface{}{
			"extra": json.MarshalRaw("this_is_extra"),
		},
	}

	got := Account{}
	err = json.Unmarshal(b, &got)
	if err != nil {
		panic(err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestAccountUnmarshal: -want/+got:\n%s", diff)
	}
}

func TestAccountKey(t *testing.T) {
	acc := &Account{
		HomeAccountID: accHID,
		Environment:   accEnv,
		Realm:         accRealm,
	}
	expectedKey := "hid-env-realm"
	actualKey := acc.Key()
	if expectedKey != actualKey {
		t.Errorf("Actual key %s differs from expected key %s", actualKey, expectedKey)
	}
}

func TestAccountMarshal(t *testing.T) {
	acc := Account{
		HomeAccountID:     accHID,
		Environment:       accEnv,
		Realm:             accRealm,
		LocalAccountID:    accLid,
		AuthorityType:     authType,
		PreferredUsername: accUser,
		AdditionalFields:  map[string]interface{}{"extra": "extra"},
	}

	want := map[string]interface{}{
		"home_account_id":  "hid",
		"environment":      "env",
		"realm":            "realm",
		"local_account_id": "lid",
		"authority_type":   authType,
		"username":         "user",
		"extra":            "extra",
	}
	b, err := json.Marshal(acc)
	if err != nil {
		panic(err)
	}

	got := map[string]interface{}{}
	if err := stdJSON.Unmarshal(b, &got); err != nil {
		panic(err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestAccountMarshal: -want/+got:\n%s", diff)
	}
}
