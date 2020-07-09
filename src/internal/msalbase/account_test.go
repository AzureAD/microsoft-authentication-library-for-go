// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"reflect"
	"testing"
)

func TestAccountPopulateFromJSONMap(t *testing.T) {
	jsonMap := map[string]interface{}{
		"home_account_id": "hid",
		"environment":     "env",
		"extra":           "this_is_extra",
		"authority_type":  "MSSTS",
	}
	expectedAccount := &Account{
		HomeAccountID:    "hid",
		Environment:      "env",
		AuthorityType:    AuthorityTypeAad,
		AdditionalFields: map[string]interface{}{"extra": "this_is_extra"},
	}
	actualAccount := &Account{}
	err := actualAccount.PopulateFromJSONMap(jsonMap)
	if err != nil {
		t.Errorf("Error is supposed to be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualAccount, expectedAccount) {
		t.Errorf("Actual account %+v differs from expected account %+v", actualAccount, expectedAccount)
	}
}

func TestAccountCreateKey(t *testing.T) {
	acc := &Account{
		HomeAccountID: "hid",
		Environment:   "env",
		Realm:         "realm",
	}
	expectedKey := "hid-env-realm"
	actualKey := acc.CreateKey()
	if !reflect.DeepEqual(expectedKey, actualKey) {
		t.Errorf("Actual key %s differs from expected key %s", actualKey, expectedKey)
	}
}

func TestAccountConvertToJSONMap(t *testing.T) {
	acc := &Account{
		HomeAccountID:     "hid",
		Environment:       "env",
		Realm:             "realm",
		LocalAccountID:    "lid",
		AuthorityType:     AuthorityTypeAad,
		PreferredUsername: "user",
		AdditionalFields:  map[string]interface{}{"extra": "extra"},
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
	actualJSONMap := acc.ConvertToJSONMap()
	if !reflect.DeepEqual(jsonMap, actualJSONMap) {
		t.Errorf("JSON account %+v differs from expected JSON account %+v", jsonMap, actualJSONMap)
	}
}
