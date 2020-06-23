// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"reflect"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

func TestCreateAcquireTokenCommonParameters(t *testing.T) {
	expectedScopes := []string{"user.read"}
	params := createAcquireTokenCommonParameters(expectedScopes)
	if params == nil {
		t.Error("Parameters cannot be nil.")
	}
	actualScopes := params.scopes
	if !reflect.DeepEqual(expectedScopes, actualScopes) {
		t.Errorf("Actual scopes %v differ from expected scopes %v", actualScopes, expectedScopes)
	}
}

func TestAugmentAuthenticationParameters(t *testing.T) {
	testScopes := []string{"user.read"}
	testTokenParams := &acquireTokenCommonParameters{testScopes}
	testAuthParams := &msalbase.AuthParametersInternal{}
	testTokenParams.augmentAuthenticationParameters(testAuthParams)
	authScopes := testAuthParams.GetScopes()
	if !reflect.DeepEqual(testScopes, authScopes) {
		t.Errorf("Actual scopes %v differ from expected scopes %v", authScopes, testScopes)
	}
}
