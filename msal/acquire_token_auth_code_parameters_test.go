// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"reflect"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

func TestCreateAcquireTokenAuthCodeParameters(t *testing.T) {
	expectedScopes := []string{"user.read"}
	params := createAcquireTokenAuthCodeParameters(expectedScopes)
	if params == nil {
		t.Error("Parameters cannot be nil.")
	}
	actualScopes := params.commonParameters.scopes
	if !reflect.DeepEqual(expectedScopes, actualScopes) {
		t.Errorf("Actual scopes %v differ from expected scopes %v", actualScopes, expectedScopes)
	}
}

func TestAugmentAuthenticationParametersForAuth(t *testing.T) {
	testScopes := []string{"user.read"}
	testAuthParams := msalbase.AuthParametersInternal{}
	testTokenCommonParams := acquireTokenCommonParameters{testScopes}
	testAuthCodeParams := acquireTokenAuthCodeParameters{
		commonParameters: testTokenCommonParams,
	}
	testAuthCodeParams.augmentAuthenticationParameters(&testAuthParams)
	actualScopes := testAuthParams.Scopes
	if !reflect.DeepEqual(testScopes, actualScopes) {
		t.Errorf("Actual scopes %v differ from expected scopes %v", actualScopes, testScopes)
	}
}
