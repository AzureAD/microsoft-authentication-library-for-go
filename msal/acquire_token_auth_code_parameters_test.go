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
	expectedRedirectURI := "http://localhost:3000/redirect"
	params := CreateAcquireTokenAuthCodeParameters(expectedScopes, expectedRedirectURI)
	if params == nil {
		t.Error("Parameters cannot be nil.")
	}
	actualScopes := params.commonParameters.scopes
	if !reflect.DeepEqual(expectedScopes, actualScopes) {
		t.Errorf("Actual scopes %v differ from expected scopes %v", actualScopes, expectedScopes)
	}
	actualRedirectURI := params.redirectURI
	if !reflect.DeepEqual(expectedRedirectURI, actualRedirectURI) {
		t.Errorf("Actual redirect URI %v differs from expected redirect URI %v", actualRedirectURI, expectedRedirectURI)
	}
}

func TestAugmentAuthenticationParametersForAuth(t *testing.T) {
	testScopes := []string{"user.read"}
	testRedirectURI := "http://localhost:3000/redirect"
	testAuthParams := &msalbase.AuthParametersInternal{}
	testTokenCommonParams := &acquireTokenCommonParameters{testScopes}
	testAuthCodeParams := &AcquireTokenAuthCodeParameters{
		commonParameters: testTokenCommonParams,
		redirectURI:      testRedirectURI,
	}
	testAuthCodeParams.augmentAuthenticationParameters(testAuthParams)
	actualScopes := testAuthParams.Scopes
	if !reflect.DeepEqual(testScopes, actualScopes) {
		t.Errorf("Actual scopes %v differ from expected scopes %v", actualScopes, testScopes)
	}
	actualRedirectURI := testAuthParams.Redirecturi
	if !reflect.DeepEqual(testRedirectURI, actualRedirectURI) {
		t.Errorf("Actual redirect URI %v differs from expected redirect URI %v", actualRedirectURI, testRedirectURI)
	}

}
