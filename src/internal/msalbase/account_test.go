// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"reflect"
	"testing"
)

var accHID = "hid"
var accEnv = "env"
var accRealm = "realm"
var authType = "MSSTS"
var accLid = "lid"
var accUser = "user"

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
	actualHID := *actualAccount.HomeAccountID
	if !reflect.DeepEqual(actualHID, accHID) {
		t.Errorf("Expected home account ID %s differs from actual home account ID %s", accHID, actualHID)
	}
	actualEnv := *actualAccount.Environment
	if !reflect.DeepEqual(actualEnv, accEnv) {
		t.Errorf("Expected environment %s differs from actual environment %s", accEnv, actualEnv)
	}
	if !reflect.DeepEqual(*actualAccount.AuthorityType, MSSTS) {
		t.Errorf("Actual auth type %v differs from expected auth type %v", actualAccount.AuthorityType, MSSTS)
	}
}

func TestAccountCreateKey(t *testing.T) {
	acc := &Account{
		HomeAccountID: &accHID,
		Environment:   &accEnv,
		Realm:         &accRealm,
	}
	expectedKey := "hid-env-realm"
	actualKey := acc.CreateKey()
	if !reflect.DeepEqual(expectedKey, actualKey) {
		t.Errorf("Actual key %s differs from expected key %s", actualKey, expectedKey)
	}
}

func TestAccountConvertToJSONMap(t *testing.T) {
	acc := &Account{
		HomeAccountID:     &accHID,
		Environment:       &accEnv,
		Realm:             &accRealm,
		LocalAccountID:    &accLid,
		AuthorityType:     &authType,
		PreferredUsername: &accUser,
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
