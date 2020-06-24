// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"reflect"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

func TestCreateAcquireTokenAuthCodeParameters(t *testing.T) {
	expectedScopes := []string{"user.read"}
	expectedRedirectURI := "http://localhost:3000/redirect"
	expectedCodeChallenge := "codeChallenge"
	params := CreateAcquireTokenAuthCodeParameters(expectedScopes, expectedRedirectURI, expectedCodeChallenge)
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
	actualCodeChallenge := params.codeChallenge
	if !reflect.DeepEqual(expectedCodeChallenge, actualCodeChallenge) {
		t.Errorf("Actual code challenge %v differs from expected code challenge %v", actualCodeChallenge, expectedCodeChallenge)
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
	actualScopes := testAuthParams.GetScopes()
	if !reflect.DeepEqual(testScopes, actualScopes) {
		t.Errorf("Actual scopes %v differ from expected scopes %v", actualScopes, testScopes)
	}
	actualRedirectURI := testAuthParams.GetRedirectURI()
	if !reflect.DeepEqual(testRedirectURI, actualRedirectURI) {
		t.Errorf("Actual redirect URI %v differs from expected redirect URI %v", actualRedirectURI, testRedirectURI)
	}

}

func TestSetCode(t *testing.T) {
	testAuthCodeParams := &AcquireTokenAuthCodeParameters{}
	expectedCode := "code"
	testAuthCodeParams.SetCode(expectedCode)
	actualCode := testAuthCodeParams.code
	if !reflect.DeepEqual(expectedCode, actualCode) {
		t.Errorf("Actual code %v differs from expected code challenge %v", actualCode, expectedCode)
	}
}

func TestSetCodeChallenge(t *testing.T) {
	testAuthCodeParams := &AcquireTokenAuthCodeParameters{}
	expectedCodeChallenge := "codeChallenge"
	testAuthCodeParams.SetCodeChallenge(expectedCodeChallenge)
	actualCodeChallenge := testAuthCodeParams.codeChallenge
	if !reflect.DeepEqual(expectedCodeChallenge, actualCodeChallenge) {
		t.Errorf("Actual code challenge %v differs from expected code challenge %v", actualCodeChallenge, expectedCodeChallenge)
	}
}

func TestSetCodeChallengeMethod(t *testing.T) {
	testAuthCodeParams := &AcquireTokenAuthCodeParameters{}
	expectedCodeChallengeMethod := "plain"
	testAuthCodeParams.SetCodeChallengeMethod(expectedCodeChallengeMethod)
	actualCodeChallengeMethod := testAuthCodeParams.codeChallengeMethod
	if !reflect.DeepEqual(expectedCodeChallengeMethod, actualCodeChallengeMethod) {
		t.Errorf("Actual code challenge method %v differs from expected code challenge method %v", actualCodeChallengeMethod, expectedCodeChallengeMethod)
	}
}
