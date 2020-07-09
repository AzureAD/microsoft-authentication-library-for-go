// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"reflect"
	"testing"
)

var appMetadata = &AppMetadata{
	ClientID:    "clientID",
	Environment: "env",
}

func TestCreateKeyForAppMetadata(t *testing.T) {
	expectedKey := "appmetadata-env-clientID"
	actualKey := appMetadata.CreateKey()
	if !reflect.DeepEqual(expectedKey, actualKey) {
		t.Errorf("Actual key %v differs from expected key %v", actualKey, expectedKey)
	}
}

func TestAppMetadataPopulateFromJSONMap(t *testing.T) {
	jsonMap := map[string]interface{}{
		"environment": "env",
		"extra":       "this_is_extra",
		"cached_at":   "100",
		"client_id":   "cid",
	}
	expectedAppMetadata := &AppMetadata{
		Environment:      "env",
		ClientID:         "cid",
		additionalFields: map[string]interface{}{"extra": "this_is_extra", "cached_at": "100"},
	}
	actualAppMetadata := &AppMetadata{}
	err := actualAppMetadata.populateFromJSONMap(jsonMap)
	if err != nil {
		t.Errorf("Error is supposed to be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualAppMetadata, expectedAppMetadata) {
		t.Errorf("Actual app metadata %+v differs from expected app metadata %+v", actualAppMetadata, expectedAppMetadata)
	}
}

func TestAppMetadataConvertToJSONMap(t *testing.T) {
	appMetadata := &AppMetadata{
		Environment:      "env",
		ClientID:         "cid",
		additionalFields: map[string]interface{}{"extra": "this_is_extra", "cached_at": "100"},
	}
	jsonMap := map[string]interface{}{
		"family_id":   "",
		"environment": "env",
		"client_id":   "cid",
		"extra":       "this_is_extra",
		"cached_at":   "100",
	}
	actualJSONMap := appMetadata.convertToJSONMap()
	if !reflect.DeepEqual(jsonMap, actualJSONMap) {
		t.Errorf("JSON app metadata %+v differs from expected JSON app metadata %+v", actualJSONMap, jsonMap)
	}
}
