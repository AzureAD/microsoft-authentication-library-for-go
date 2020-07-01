// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"reflect"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

func TestCheckAlias(t *testing.T) {
	aliases := []string{"testOne", "testTwo", "testThree"}
	aliasOne := "noTest"
	aliasTwo := "testOne"
	if checkAlias(aliasOne, aliases) {
		t.Errorf("%v isn't supposed to be in %v", aliasOne, aliases)
	}
	if !checkAlias(aliasTwo, aliases) {
		t.Errorf("%v is supposed to be in %v", aliasTwo, aliases)
	}
}

func TestIsMatchingScopes(t *testing.T) {
	scopesOne := []string{"user.read", "openid", "user.write"}
	scopesTwo := "openid user.write user.read"
	if !isMatchingScopes(scopesOne, scopesTwo) {
		t.Errorf("Scopes %v and %v are supposed to be the same", scopesOne, scopesTwo)
	}
	errorScopes := "openid user.read hello"
	if isMatchingScopes(scopesOne, errorScopes) {
		t.Errorf("Scopes %v and %v are not supposed to be the same", scopesOne, errorScopes)
	}
}

func TestReadAllAccounts(t *testing.T) {
	storageManager := CreateStorageManager()
	testAccOne := msalbase.CreateAccount("hid", "env", "realm", "lid", msalbase.AuthorityTypeAad, "username")
	testAccTwo := msalbase.CreateAccount("HID", "ENV", "REALM", "LID", msalbase.AuthorityTypeAad, "USERNAME")
	storageManager.accounts[testAccOne.CreateKey()] = testAccOne
	storageManager.accounts[testAccTwo.CreateKey()] = testAccTwo
	actualAccounts := storageManager.ReadAllAccounts()
	expectedAccounts := []*msalbase.Account{testAccOne, testAccTwo}
	if !reflect.DeepEqual(actualAccounts, expectedAccounts) {
		t.Errorf("Actual accounts %v differ from expected accounts %v", actualAccounts, expectedAccounts)
	}
}

func TestReadAccessToken(t *testing.T) {

}

func TestWriteAccessToken(t *testing.T) {
	storageManager := CreateStorageManager()
	testAccessToken := CreateAccessTokenCacheItem(
		"hid",
		"env",
		"realm",
		"cid",
		1,
		1,
		1,
		"openid",
		"secret",
	)
	key := testAccessToken.CreateKey()
	err := storageManager.WriteAccessToken(testAccessToken)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(storageManager.accessTokens[key], testAccessToken) {
		t.Errorf("Added access token %v differs from expected access token %v",
			storageManager.accessTokens[key],
			testAccessToken)
	}
}

func TestWriteAccount(t *testing.T) {
	storageManager := CreateStorageManager()
	testAcc := msalbase.CreateAccount("hid", "env", "realm", "lid", msalbase.AuthorityTypeAad, "username")
	key := testAcc.CreateKey()
	err := storageManager.WriteAccount(testAcc)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(storageManager.accounts[key], testAcc) {
		t.Errorf("Added account %v differs from expected account %v", storageManager.accounts[key], testAcc)
	}
}

func TestWriteAppMetadata(t *testing.T) {
	storageManager := CreateStorageManager()
	testAppMeta := CreateAppMetadata("fid", "cid", "env")
	key := testAppMeta.CreateKey()
	err := storageManager.WriteAppMetadata(testAppMeta)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(storageManager.appMetadatas[key], testAppMeta) {
		t.Errorf("Added app metadata %v differs from expected account %v", storageManager.appMetadatas[key], testAppMeta)
	}
}

func TestWriteIDToken(t *testing.T) {
	storageManager := CreateStorageManager()
	testIDToken := CreateIDTokenCacheItem(
		"hid",
		"env",
		"realm",
		"cid",
		"secret",
	)
	key := testIDToken.CreateKey()
	err := storageManager.WriteIDToken(testIDToken)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(storageManager.idTokens[key], testIDToken) {
		t.Errorf("Added ID token %v differs from expected ID Token %v",
			storageManager.idTokens[key],
			testIDToken)
	}
}

func TestWriteRefreshToken(t *testing.T) {
	storageManager := CreateStorageManager()
	testRefreshToken := CreateRefreshTokenCacheItem(
		"hid",
		"env",
		"cid",
		"secret",
		"fid",
	)
	key := testRefreshToken.CreateKey()
	err := storageManager.WriteRefreshToken(testRefreshToken)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(storageManager.refreshTokens[key], testRefreshToken) {
		t.Errorf("Added refresh token %v differs from expected refresh token %v",
			storageManager.refreshTokens[key],
			testRefreshToken)
	}
}
