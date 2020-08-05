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

func TestCreateAuthenticationResultFromStorageTokenResponse(t *testing.T) {
	at := new(mockAccessToken)
	id := new(mockCredential)
	acc := &Account{}
	atSecret := "secret"
	storageToken := &StorageTokenResponse{
		accessToken: at,
		idToken:     id,
		account:     acc,
	}
	at.On("GetSecret").Return(atSecret)
	at.On("GetExpiresOn").Return("1592049600")
	at.On("GetScopes").Return("profile openid user.read")
	id.On("GetSecret").Return("x.e30")
	expAuthResult := &AuthenticationResult{
		Account:       acc,
		AccessToken:   atSecret,
		idToken:       &IDToken{},
		ExpiresOn:     time.Date(2020, time.June, 13, 12, 0, 0, 0, time.UTC),
		GrantedScopes: []string{"profile", "openid", "user.read"},
	}
	actualAuthResult, err := CreateAuthenticationResultFromStorageTokenResponse(storageToken)
	if err != nil {
		t.Errorf("Error should be nil but it is %v", err)
	}
	if !reflect.DeepEqual(actualAuthResult.Account, acc) &&
		!reflect.DeepEqual(actualAuthResult.AccessToken, atSecret) &&
		!reflect.DeepEqual(actualAuthResult.idToken, &IDToken{}) &&
		!reflect.DeepEqual(actualAuthResult.ExpiresOn, time.Date(2020, time.June, 13, 12, 0, 0, 0, time.UTC)) &&
		!reflect.DeepEqual(actualAuthResult.GrantedScopes, []string{"profile", "openid", "user.read"}) {
		t.Errorf("Actual authentication result %+v differs from expected authentication result %+v", actualAuthResult, expAuthResult)
	}
}
