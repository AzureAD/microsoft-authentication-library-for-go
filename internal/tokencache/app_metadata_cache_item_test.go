// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"reflect"
	"testing"

	"github.com/kylelemons/godebug/pretty"
)

var (
	appClient = "cid"
	appEnv    = "env"
	fam       = ""
	appMeta   = &appMetadata{
		ClientID:    appClient,
		Environment: appEnv,
		FamilyID:    "",
	}
)

func TestCreateKeyForAppMetadata(t *testing.T) {
	want := "appmetadata-env-cid"
	got := appMeta.CreateKey()
	if want != got {
		t.Errorf("actual key %v differs from expected key %v", want, got)
	}
}

func TestAppMetadataPopulateFromJSONMap(t *testing.T) {
	jsonMap := map[string]interface{}{
		"environment": "env",
		"extra":       "this_is_extra",
		"cached_at":   "100",
		"client_id":   "cid",
		"family_id":   nil,
	}
	actualAppMetadata := &appMetadata{}
	err := actualAppMetadata.populateFromJSONMap(jsonMap)
	if err != nil {
		t.Errorf("Error is supposed to be nil, but it is %v", err)
	}
	actualEnv := actualAppMetadata.Environment
	if !reflect.DeepEqual(actualEnv, appEnv) {
		t.Errorf("Actual app metadata environment %+v differs from expected app metadata environment %+v",
			actualEnv, appEnv)
	}
	actualClient := actualAppMetadata.ClientID
	if !reflect.DeepEqual(actualClient, appClient) {
		t.Errorf("Actual app metadata client ID %s differs from expected app metadata client ID %s",
			actualClient, appClient)
	}
	if actualAppMetadata.FamilyID != "" {
		t.Errorf("Family ID should be nil, not %v", actualAppMetadata.FamilyID)
	}
}

func TestAppMetadataConvertToJSONMap(t *testing.T) {
	appMetadata := &appMetadata{
		Environment:      "",
		ClientID:         appClient,
		FamilyID:         fam,
		additionalFields: map[string]interface{}{"extra": "this_is_extra", "cached_at": "100"},
	}
	want := map[string]interface{}{
		"client_id": "cid",
		"extra":     "this_is_extra",
		"cached_at": "100",
	}
	got, err := appMetadata.convertToJSONMap()
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestAppMetadataConvertToJSONMap: -want/+got:\n%s", diff)
	}
	/*
		if !reflect.DeepEqual(jsonMap, actualJSONMap) {
			t.Errorf("JSON app metadata %+v differs from expected JSON app metadata %+v", actualJSONMap, jsonMap)
		}
	*/
}
