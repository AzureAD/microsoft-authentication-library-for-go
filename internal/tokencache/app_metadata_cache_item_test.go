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
	appClient = "cid"
	appEnv    = "env"
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

func TestAppMetadataUnmarshal(t *testing.T) {
	jsonMap := map[string]interface{}{
		"environment": "env",
		"extra":       "this_is_extra",
		"cached_at":   "100",
		"client_id":   "cid",
		"family_id":   nil,
	}
	want := appMetadata{
		ClientID:    "cid",
		Environment: "env",
		AdditionalFields: map[string]interface{}{
			"extra":     json.MarshalRaw("this_is_extra"),
			"cached_at": json.MarshalRaw("100"),
		},
	}

	b, err := stdJSON.Marshal(jsonMap)
	if err != nil {
		panic(err)
	}
	got := appMetadata{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("TestAppMetadataUnmarshal(unmarshal): got err == %s, want err == nil", err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Fatalf("TestAppMetadataUnmarshal: -want/+got:\n%s", diff)
	}
}

func TestAppMetadataMarshal(t *testing.T) {
	appMetadata := appMetadata{
		Environment: "",
		ClientID:    appClient,
		FamilyID:    "",
		AdditionalFields: map[string]interface{}{
			"extra":     "this_is_extra",
			"cached_at": "100",
		},
	}

	want := map[string]interface{}{
		"client_id": "cid",
		"extra":     "this_is_extra",
		"cached_at": "100",
	}

	b, err := json.Marshal(appMetadata)
	if err != nil {
		panic(err)
	}
	got := map[string]interface{}{}
	if err := stdJSON.Unmarshal(b, &got); err != nil {
		t.Fatalf("TestAppMetadataMarshal(unmarshal): err == %s, want err == nil", err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestAppMetadataConvertToJSONMap: -want/+got:\n%s", diff)
	}
}
