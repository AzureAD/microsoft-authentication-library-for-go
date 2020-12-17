// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"reflect"
	"testing"
)

func TestDecodeJWT(t *testing.T) {
	encodedStr := "aGVsbG8"
	expectedStr := []byte("hello")
	actualString, err := DecodeJWT(encodedStr)
	if err != nil {
		t.Errorf("Error should be nil but it is %v", err)
	}
	if !reflect.DeepEqual(expectedStr, actualString) {
		t.Errorf("Actual decoded string %s differs from expected decoded string %s", actualString, expectedStr)
	}
}

func TestGetLocalAccountID(t *testing.T) {
	id := &IDToken{
		Subject: "sub",
	}
	actualLID := id.GetLocalAccountID()
	if !reflect.DeepEqual("sub", actualLID) {
		t.Errorf("Expected local account ID sub differs from actual local account ID %s", actualLID)
	}
	id.Oid = "oid"
	actualLID = id.GetLocalAccountID()
	if !reflect.DeepEqual("oid", actualLID) {
		t.Errorf("Expected local account ID oid differs from actual local account ID %s", actualLID)
	}
}
