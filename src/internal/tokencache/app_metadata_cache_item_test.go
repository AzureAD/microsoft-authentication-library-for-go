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
