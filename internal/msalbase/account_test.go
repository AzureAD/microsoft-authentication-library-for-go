// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	stdJSON "encoding/json"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/json"

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

var testAccount = Account{
	HomeAccountID:     accHID,
	PreferredUsername: accUser,
	Environment:       accEnv,
}

func TestAccountUnmarshal(t *testing.T) {
	jsonMap := map[string]interface{}{
		"home_account_id": "hid",
		"environment":     "env",
		"extra":           "this_is_extra",
		"authority_type":  "MSSTS",
	}

	b, err := stdJSON.Marshal(jsonMap)
	if err != nil {
		panic(err)
	}

	want := Account{
		HomeAccountID: accHID,
		Environment:   accEnv,
		AuthorityType: MSSTS,
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

func TestAccountCreateKey(t *testing.T) {
	acc := &Account{
		HomeAccountID: accHID,
		Environment:   accEnv,
		Realm:         accRealm,
	}
	expectedKey := "hid-env-realm"
	actualKey := acc.CreateKey()
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
		"authority_type":   "MSSTS",
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

func TestGetHomeAccountIDForAccount(t *testing.T) {
	if testAccount.GetHomeAccountID() != accHID {
		t.Errorf("Actual home account ID %s differs from expected home account ID %s", testAccount.GetHomeAccountID(), accHID)
	}
}

func TestGetUsernameForAccount(t *testing.T) {
	if testAccount.GetUsername() != accUser {
		t.Errorf("Actual username %s differs from expected username %s", testAccount.GetUsername(), accUser)
	}
}

func TestGetEnvironmentForAccount(t *testing.T) {
	if testAccount.GetEnvironment() != accEnv {
		t.Errorf("Actual environment %s differs from expected environment %s", testAccount.GetEnvironment(), accEnv)
	}
}
