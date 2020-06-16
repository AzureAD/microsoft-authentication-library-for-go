// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"reflect"
	"testing"
)

func TestCreateAuthorizationCodeURLParameters(t *testing.T) {
	testAuthParams := &AuthParametersInternal{}
	testCodeChallenge := "codeChallenge"
	testCodeChallengeMethod := "plain"
	authCodeURLParams := CreateAuthorizationCodeURLParameters(testAuthParams, testCodeChallenge, testCodeChallengeMethod)
	if authCodeURLParams == nil {
		t.Error("Parameters cannot be nil")
	}
	actualAuthParams := authCodeURLParams.authParameters
	if !reflect.DeepEqual(actualAuthParams, testAuthParams) {
		t.Errorf("Actual authorization parameters %v differ from expected authorization parameters %v", actualAuthParams, testAuthParams)
	}
	actualResponseType := authCodeURLParams.responseType
	if !reflect.DeepEqual(actualResponseType, "code") {
		t.Errorf("Actual response type %v differs from expected response type code", actualResponseType)
	}
	actualCodeChallenge := authCodeURLParams.codeChallenge
	if !reflect.DeepEqual(actualCodeChallenge, testCodeChallenge) {
		t.Errorf("Actual code challenge %v differs from expected code challenge %v", actualCodeChallenge, testCodeChallenge)
	}
	actualCodeChallengeMethod := authCodeURLParams.codeChallengeMethod
	if !reflect.DeepEqual(actualCodeChallengeMethod, testCodeChallengeMethod) {
		t.Errorf("Actual code challenge method %v differs from expected code challenge method %v", actualCodeChallengeMethod, testCodeChallengeMethod)
	}
}

func TestGetSpaceSeparatedScopes(t *testing.T) {
	testScopes := []string{"user.read", "openid"}
	testAuthParams := &AuthParametersInternal{scopes: testScopes}
	expectedScopes := "user.read openid"
	authCodeURLParams := &AuthorizationCodeURLParameters{authParameters: testAuthParams}
	actualSpaceSepScopes := authCodeURLParams.GetSpaceSeparatedScopes()
	if !reflect.DeepEqual(actualSpaceSepScopes, expectedScopes) {
		t.Errorf("Actual separated scopes %v differs from expected space separated scopes %v", actualSpaceSepScopes, expectedScopes)
	}
}
