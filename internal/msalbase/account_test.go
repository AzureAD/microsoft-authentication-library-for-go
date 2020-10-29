// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"reflect"
	"testing"
)

var (
	accHID   = "hid"
	accEnv   = "env"
	accRealm = "realm"
	authType = "MSSTS"
	accLid   = "lid"
	accUser  = "user"
)

var testAccount = &Account{
	HomeAccountID:     accHID,
	PreferredUsername: accUser,
	Environment:       accEnv,
}

func TestAccountPopulateFromJSONMap(t *testing.T) {
	jsonMap := map[string]interface{}{
		"home_account_id": "hid",
		"environment":     "env",
		"extra":           "this_is_extra",
		"authority_type":  "MSSTS",
	}

	actualAccount := &Account{}
	err := actualAccount.PopulateFromJSONMap(jsonMap)
	if err != nil {
		t.Errorf("Error is supposed to be nil, but it is %v", err)
	}
	if actualAccount.HomeAccountID != accHID {
		t.Errorf("Expected home account ID %s differs from actual home account ID %s", accHID, actualAccount.HomeAccountID)
	}
	if actualAccount.Environment != accEnv {
		t.Errorf("Expected environment %s differs from actual environment %s", accEnv, actualAccount.Environment)
	}
	if actualAccount.AuthorityType != MSSTS {
		t.Errorf("Actual auth type %v differs from expected auth type %v", actualAccount.AuthorityType, MSSTS)
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

func TestAccountConvertToJSONMap(t *testing.T) {
	acc := &Account{
		HomeAccountID:     accHID,
		Environment:       accEnv,
		Realm:             accRealm,
		LocalAccountID:    accLid,
		AuthorityType:     authType,
		PreferredUsername: accUser,
		additionalFields:  map[string]interface{}{"extra": "extra"},
	}
	jsonMap := map[string]interface{}{
		"home_account_id":  "hid",
		"environment":      "env",
		"realm":            "realm",
		"local_account_id": "lid",
		"authority_type":   "MSSTS",
		"username":         "user",
		"extra":            "extra",
	}
	actualJSONMap, err := acc.ConvertToJSONMap()
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(jsonMap, actualJSONMap) {
		t.Errorf("JSON account %+v differs from expected JSON account %+v", jsonMap, actualJSONMap)
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
