// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"reflect"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

func TestAugmentAuthenticationParametersDeviceCode(t *testing.T) {
	testScopes := []string{"user.read"}
	testAuthParams := &msalbase.AuthParametersInternal{}
	testTokenCommonParams := &acquireTokenCommonParameters{testScopes}
	testDeviceCodeParams := &AcquireTokenDeviceCodeParameters{
		commonParameters: testTokenCommonParams,
	}
	testDeviceCodeParams.augmentAuthenticationParameters(testAuthParams)
	actualScopes := testAuthParams.Scopes
	if !reflect.DeepEqual(testScopes, actualScopes) {
		t.Errorf("Actual scopes %v differ from expected scopes %v", actualScopes, testScopes)
	}
}
