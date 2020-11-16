// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"reflect"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

func TestAugmentAuthenticationParametersSilent(t *testing.T) {
	testScopes := []string{"user.read"}
	testAuthParams := msalbase.AuthParametersInternal{}
	testTokenCommonParams := acquireTokenCommonParameters{testScopes}
	homeAccountID := "hid"
	testAccount := msalbase.Account{
		HomeAccountID: homeAccountID,
	}
	testSilentParams := AcquireTokenSilentParameters{
		commonParameters: testTokenCommonParams,
		account:          testAccount,
	}
	testSilentParams.augmentAuthenticationParameters(&testAuthParams)
	actualScopes := testAuthParams.Scopes
	if !reflect.DeepEqual(testScopes, actualScopes) {
		t.Errorf("Actual scopes %v differ from expected scopes %v", actualScopes, testScopes)
	}
	actualHomeAccountID := testAuthParams.HomeaccountID
	if !reflect.DeepEqual(actualHomeAccountID, homeAccountID) {
		t.Errorf("Actual home account ID %s differs from expected home account ID %s", actualHomeAccountID, homeAccountID)
	}
}
