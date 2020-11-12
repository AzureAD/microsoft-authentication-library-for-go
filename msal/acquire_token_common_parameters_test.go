// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"reflect"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

func TestCreateAcquireTokenCommonParameters(t *testing.T) {
	expectedScopes := []string{"user.read"}
	params := createAcquireTokenCommonParameters([]string{"User.Read"})
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
	authScopes := testAuthParams.Scopes
	if !reflect.DeepEqual(testScopes, authScopes) {
		t.Errorf("Actual scopes %v differ from expected scopes %v", authScopes, testScopes)
	}
}
