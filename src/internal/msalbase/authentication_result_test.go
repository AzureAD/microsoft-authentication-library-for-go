// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"reflect"
	"testing"
	"time"
)

func TestCreateAuthenticationResult(t *testing.T) {
	testAccessToken := "accessToken"
	testExpiresOn := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	testIDToken := &IDToken{}
	testGrantedScopes := []string{"user.read"}
	testDeclinedScopesWithoutError := []string{}
	testDeclinedScopesWithError := []string{"openid"}
	testTokenResponseWithoutError := &TokenResponse{
		AccessToken:    testAccessToken,
		ExpiresOn:      testExpiresOn,
		IDToken:        testIDToken,
		GrantedScopes:  testGrantedScopes,
		declinedScopes: testDeclinedScopesWithoutError,
	}
	testTokenResponseWithError := &TokenResponse{
		AccessToken:    testAccessToken,
		ExpiresOn:      testExpiresOn,
		IDToken:        testIDToken,
		GrantedScopes:  testGrantedScopes,
		declinedScopes: testDeclinedScopesWithError,
	}
	testAccount := &Account{}
	authResult, err := CreateAuthenticationResult(testTokenResponseWithoutError, testAccount)
	if err != nil {
		t.Errorf("There should be no error, however there is an error saying %v", err)
	}
	actualAccount := authResult.Account
	if !reflect.DeepEqual(actualAccount, testAccount) {
		t.Errorf("Actual account %v differs from expected account %v", actualAccount, testAccount)
	}
	actualIDToken := authResult.idToken
	if !reflect.DeepEqual(actualIDToken, testIDToken) {
		t.Errorf("Actual ID token %v differs from expected ID Token %v", actualIDToken, testIDToken)
	}
	actualAccessToken := authResult.AccessToken
	if !reflect.DeepEqual(actualAccessToken, testAccessToken) {
		t.Errorf("Actual access token %v differs from expected access token %v", actualAccessToken, testAccessToken)
	}
	actualExpiresOn := authResult.ExpiresOn
	if !reflect.DeepEqual(actualExpiresOn, testExpiresOn) {
		t.Errorf("Actual expires on %v differs from expected expires on %v", actualExpiresOn, testExpiresOn)
	}
	actualGrantedScopes := authResult.GrantedScopes
	if !reflect.DeepEqual(actualGrantedScopes, testGrantedScopes) {
		t.Errorf("Actual granted scopes %v differ from expected granted scopes %v", actualGrantedScopes, testGrantedScopes)
	}
	actualDeclinedScopes := authResult.DeclinedScopes
	if !reflect.DeepEqual(actualDeclinedScopes, testDeclinedScopesWithoutError) {
		t.Errorf("Actual declined scopes %v differ from expected declined scopes %v", actualDeclinedScopes, testDeclinedScopesWithoutError)
	}
	authResult, err = CreateAuthenticationResult(testTokenResponseWithError, testAccount)
	if err == nil {
		t.Error("Error should not be nil")
	}
	if authResult != nil {
		t.Errorf("Authentication result should be nil, not %v", authResult)
	}
}
