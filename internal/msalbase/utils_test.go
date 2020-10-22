// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"reflect"
	"testing"
)

func TestConcatenateScopes(t *testing.T) {
	expectedScopes := "profile openid user.read"
	actualScopes := ConcatenateScopes([]string{"profile", "openid", "user.read"})
	if !reflect.DeepEqual(expectedScopes, actualScopes) {
		t.Errorf("Expected scopes %s differ from actual scopes %s", expectedScopes, actualScopes)
	}
}

func TestSplitScopes(t *testing.T) {
	expectedScopes := []string{"profile", "openid", "user.read"}
	actualScopes := SplitScopes("profile openid user.read")
	if !reflect.DeepEqual(expectedScopes, actualScopes) {
		t.Errorf("Expected scopes %v differ from actual scopes %v", expectedScopes, actualScopes)
	}
}

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
