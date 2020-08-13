// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"io/ioutil"
	"os"
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
	storageManager := &defaultStorageManager{
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
	testAccOne := msalbase.CreateAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")
	testAccTwo := msalbase.CreateAccount("HID", "ENV", "REALM", "LID", msalbase.MSSTS, "USERNAME")
	storageManager.accounts[testAccOne.CreateKey()] = testAccOne
	storageManager.accounts[testAccTwo.CreateKey()] = testAccTwo
	actualAccounts := storageManager.ReadAllAccounts()
	expectedAccounts := []*msalbase.Account{testAccOne, testAccTwo}
	checkEqual := func(listOne []*msalbase.Account, listTwo []*msalbase.Account) bool {
		if len(listOne) != len(listTwo) {
			return false
		}
		counter := 0
		for _, accOne := range listOne {
			for _, accTwo := range listTwo {
				if reflect.DeepEqual(accOne, accTwo) {
					counter++
				}
			}
		}
		return counter == len(listOne)
	}
	if !checkEqual(actualAccounts, expectedAccounts) {
		t.Errorf("Actual accounts %v differ from expected accounts %v", actualAccounts, expectedAccounts)
	}
}

func TestDeleteAccounts(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
	testAccOne := msalbase.CreateAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")
	testAccTwo := msalbase.CreateAccount("HID", "ENV", "REALM", "LID", msalbase.MSSTS, "USERNAME")
	storageManager.accounts[testAccOne.CreateKey()] = testAccOne
	storageManager.accounts[testAccTwo.CreateKey()] = testAccTwo
	err := storageManager.DeleteAccounts("hid", []string{"hello", "env", "test"})
	if err != nil {
		t.Errorf("Error is supposed to be nil; instead it is %v", err)
	}
}

func TestReadAccessToken(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
	testAccessToken := createAccessTokenCacheItem(
		"hid",
		"env",
		"realm",
		"cid",
		1,
		1,
		1,
		"openid user.read",
		"secret",
	)
	storageManager.accessTokens[testAccessToken.CreateKey()] = testAccessToken
	retAccessToken := storageManager.ReadAccessToken(
		"hid",
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
		[]string{"user.read", "openid"},
	)
	if !reflect.DeepEqual(testAccessToken, retAccessToken) {
		t.Errorf("Returned access token %v is not the same as expected access token %v", retAccessToken, testAccessToken)
	}
	readAccessToken := storageManager.ReadAccessToken(
		"this_should_break_it",
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
		[]string{"user.read", "openid"},
	)
	if readAccessToken != nil {
		t.Errorf("Returned access token should be nil; instead it is %v", readAccessToken)
	}
}

func TestWriteAccessToken(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
	testAccessToken := createAccessTokenCacheItem(
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

func TestReadAccount(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
	testAcc := msalbase.CreateAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")
	storageManager.accounts[testAcc.CreateKey()] = testAcc
	returnedAccount := storageManager.ReadAccount("hid", []string{"hello", "env", "test"}, "realm")
	if !reflect.DeepEqual(returnedAccount, testAcc) {
		t.Errorf("Returned account %v differs from expected account %v", returnedAccount, testAcc)
	}
	readAccount := storageManager.ReadAccount("this_should_break_it", []string{"hello", "env", "test"}, "realm")
	if readAccount != nil {
		t.Errorf("Returned account should be nil, instead it is %v", readAccount)
	}
}

func TestWriteAccount(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
	testAcc := msalbase.CreateAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")
	key := testAcc.CreateKey()
	err := storageManager.WriteAccount(testAcc)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(storageManager.accounts[key], testAcc) {
		t.Errorf("Added account %v differs from expected account %v", storageManager.accounts[key], testAcc)
	}
}

func TestReadAppMetadata(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
	testAppMeta := createAppMetadata("fid", "cid", "env")
	storageManager.appMetadatas[testAppMeta.CreateKey()] = testAppMeta
	returnedAppMeta := storageManager.ReadAppMetadata([]string{"hello", "test", "env"}, "cid")
	if !reflect.DeepEqual(returnedAppMeta, testAppMeta) {
		t.Errorf("Returned app metadata %v differs from expected app metadata %v", returnedAppMeta, testAppMeta)
	}
	readAppMeta := storageManager.ReadAppMetadata([]string{"hello", "test", "env"}, "break_this")
	if readAppMeta != nil {
		t.Errorf("Returned app metadata should be nil; instead it is %v", readAppMeta)
	}
}

func TestWriteAppMetadata(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
	testAppMeta := createAppMetadata("fid", "cid", "env")
	key := testAppMeta.CreateKey()
	err := storageManager.WriteAppMetadata(testAppMeta)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(storageManager.appMetadatas[key], testAppMeta) {
		t.Errorf("Added app metadata %v differs from expected account %v", storageManager.appMetadatas[key], testAppMeta)
	}
}

func TestReadIDToken(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
	testIDToken := createIDTokenCacheItem(
		"hid",
		"env",
		"realm",
		"cid",
		"secret",
	)
	storageManager.idTokens[testIDToken.CreateKey()] = testIDToken
	returnedIDToken := storageManager.ReadIDToken(
		"hid",
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
	)
	if !reflect.DeepEqual(testIDToken, returnedIDToken) {
		t.Errorf("Returned ID token %v differs from expected ID token %v", returnedIDToken, testIDToken)
	}
	readIDToken := storageManager.ReadIDToken(
		"this_should_break_it",
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
	)
	if readIDToken != nil {
		t.Errorf("Returned ID token should be nil; instead it is %v", readIDToken)
	}
}

func TestWriteIDToken(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
	testIDToken := createIDTokenCacheItem(
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

func TestReadRefreshToken(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
	testRefreshTokenWithFID := createRefreshTokenCacheItem(
		"hid",
		"env",
		"cid",
		"secret",
		"fid",
	)
	storageManager.refreshTokens[testRefreshTokenWithFID.CreateKey()] = testRefreshTokenWithFID
	returnedRT := storageManager.ReadRefreshToken(
		"hid",
		[]string{"test", "env", "hello"},
		"fid",
		"cid",
	)
	if !reflect.DeepEqual(testRefreshTokenWithFID, returnedRT) {
		t.Errorf("Returned refresh token %v differs from expected refresh token %v",
			returnedRT,
			testRefreshTokenWithFID)
	}
	returnedRT = storageManager.ReadRefreshToken(
		"hid",
		[]string{"test", "env", "hello"},
		"",
		"CID",
	)
	if !reflect.DeepEqual(testRefreshTokenWithFID, returnedRT) {
		t.Errorf("Returned refresh token %v differs from expected refresh token %v",
			returnedRT,
			testRefreshTokenWithFID)
	}
	testRefreshTokenWoFID := createRefreshTokenCacheItem(
		"hid",
		"env",
		"cid",
		"secret",
		"",
	)
	storageManager.refreshTokens[testRefreshTokenWoFID.CreateKey()] = testRefreshTokenWoFID
	returnedRT = storageManager.ReadRefreshToken(
		"hid",
		[]string{"test", "env", "hello"},
		"fid",
		"cid",
	)
	if !reflect.DeepEqual(testRefreshTokenWithFID, returnedRT) {
		t.Errorf("Returned refresh token %v differs from expected refresh token %v",
			returnedRT,
			testRefreshTokenWithFID)
	}
	returnedRT = storageManager.ReadRefreshToken(
		"hid",
		[]string{"test", "env", "hello"},
		"",
		"cid",
	)
	if !reflect.DeepEqual(testRefreshTokenWithFID, returnedRT) {
		t.Errorf("Returned refresh token %v differs from expected refresh token %v",
			returnedRT,
			testRefreshTokenWithFID)
	}
}

func TestWriteRefreshToken(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
	testRefreshToken := createRefreshTokenCacheItem(
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

func TestStorageManagerSerialize(t *testing.T) {
	manager := &defaultStorageManager{
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
	manager.accessTokens = map[string]*accessTokenCacheItem{
		"an-entry": {
			additionalFields: map[string]interface{}{"foo": "bar"},
		},
		"uid.utid-login.windows.net-accesstoken-my_client_id-contoso-s2 s1 s3": {
			Environment:                    &defaultEnvironment,
			CredentialType:                 &accessTokenCred,
			Secret:                         &accessTokenSecret,
			Realm:                          &defaultRealm,
			Scopes:                         &defaultScopes,
			ClientID:                       &defaultClientID,
			CachedAt:                       &atCached,
			HomeAccountID:                  &defaultHID,
			ExpiresOnUnixTimestamp:         &atExpires,
			ExtendedExpiresOnUnixTimestamp: &atExpires,
			additionalFields:               make(map[string]interface{}),
		},
	}
	manager.refreshTokens = map[string]*refreshTokenCacheItem{
		"uid.utid-login.windows.net-refreshtoken-my_client_id--s2 s1 s3": {
			Target:           &defaultScopes,
			Environment:      &defaultEnvironment,
			CredentialType:   &rtCredType,
			Secret:           &rtSecret,
			ClientID:         &defaultClientID,
			HomeAccountID:    &defaultHID,
			additionalFields: make(map[string]interface{}),
		},
	}
	manager.idTokens = map[string]*idTokenCacheItem{
		"uid.utid-login.windows.net-idtoken-my_client_id-contoso-": {
			Realm:            &defaultRealm,
			Environment:      &defaultEnvironment,
			CredentialType:   &idCred,
			Secret:           &idSecret,
			ClientID:         &defaultClientID,
			HomeAccountID:    &defaultHID,
			additionalFields: make(map[string]interface{}),
		},
	}
	manager.accounts = map[string]*msalbase.Account{
		"uid.utid-login.windows.net-contoso": {
			PreferredUsername: &accUser,
			LocalAccountID:    &accLID,
			Realm:             &defaultRealm,
			Environment:       &defaultEnvironment,
			HomeAccountID:     &defaultHID,
			AuthorityType:     &accAuth,
		},
	}
	manager.appMetadatas = map[string]*appMetadata{
		"appmetadata-login.windows.net-my_client_id": {
			Environment:      &defaultEnvironment,
			FamilyID:         nil,
			ClientID:         &defaultClientID,
			additionalFields: make(map[string]interface{}),
		},
	}
	_, err := manager.Serialize()
	if err != nil {
		t.Errorf("Error should be nil; instead it is %v", err)
	}
}

func TestStorageManagerDeserialize(t *testing.T) {
	manager := &defaultStorageManager{
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
	jsonFile, err := os.Open(testFile)
	testCache, err := ioutil.ReadAll(jsonFile)
	jsonFile.Close()
	err = manager.Deserialize(testCache)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	actualATSecret := *manager.accessTokens["uid.utid-login.windows.net-accesstoken-my_client_id-contoso-s2 s1 s3"].Secret
	if !reflect.DeepEqual(accessTokenSecret, actualATSecret) {
		t.Errorf("Expected access token secret %+v differs from actual access token secret %+v", accessTokenSecret, actualATSecret)
	}
	actualRTSecret := *manager.refreshTokens["uid.utid-login.windows.net-refreshtoken-my_client_id--s2 s1 s3"].Secret
	if !reflect.DeepEqual(rtSecret, actualRTSecret) {
		t.Errorf("Expected refresh tokens %+v differ from actual refresh tokens %+v", rtSecret, actualRTSecret)
	}
	actualIDSecret := *manager.idTokens["uid.utid-login.windows.net-idtoken-my_client_id-contoso-"].Secret
	if !reflect.DeepEqual(idSecret, actualIDSecret) {
		t.Errorf("Expected ID tokens %+v differ from actual ID tokens %+v", idSecret, actualIDSecret)
	}
	actualUser := *manager.accounts["uid.utid-login.windows.net-contoso"].PreferredUsername
	if !reflect.DeepEqual(actualUser, accUser) {
		t.Errorf("Actual account username %+s differs from expected account username %+v", actualUser, accUser)
	}
	if manager.appMetadatas["appmetadata-login.windows.net-my_client_id"].FamilyID != nil {
		t.Errorf("Expected app metadata family ID is nil, instead it is %s", *manager.appMetadatas["appmetadata-login.windows.net-my_client_id"].FamilyID)
	}
}
