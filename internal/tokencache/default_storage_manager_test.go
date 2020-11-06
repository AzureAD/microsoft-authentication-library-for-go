// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/kylelemons/godebug/pretty"
)

func createDefaultStorageManager() *defaultStorageManager {
	return &defaultStorageManager{
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
}

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
	storageManager := createDefaultStorageManager()
	testAccOne := msalbase.NewAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")
	testAccTwo := msalbase.NewAccount("HID", "ENV", "REALM", "LID", msalbase.MSSTS, "USERNAME")
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
				if diff := (&pretty.Config{IncludeUnexported: false}).Compare(accOne, accTwo); diff != "" {
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
	storageManager := createDefaultStorageManager()
	testAccOne := msalbase.NewAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")
	testAccTwo := msalbase.NewAccount("HID", "ENV", "REALM", "LID", msalbase.MSSTS, "USERNAME")
	storageManager.accounts[testAccOne.CreateKey()] = testAccOne
	storageManager.accounts[testAccTwo.CreateKey()] = testAccTwo
	err := storageManager.DeleteAccounts("hid", []string{"hello", "env", "test"})
	if err != nil {
		t.Errorf("Error is supposed to be nil; instead it is %v", err)
	}
}

func TestReadAccessToken(t *testing.T) {
	storageManager := createDefaultStorageManager()
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
	if diff := (&pretty.Config{IncludeUnexported: false}).Compare(testAccessToken, retAccessToken); diff != "" {
		t.Errorf("Returned access token is not the same as expected access token: -want/+got:\n %s", diff)
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
	storageManager := createDefaultStorageManager()
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
	if diff := (&pretty.Config{IncludeUnexported: false}).Compare(testAccessToken, storageManager.accessTokens[key]); diff != "" {
		t.Errorf("Added access token differs from expected access token: -want/+got:\n %s", diff)
	}
}

func TestReadAccount(t *testing.T) {
	storageManager := createDefaultStorageManager()
	testAcc := msalbase.NewAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")
	storageManager.accounts[testAcc.CreateKey()] = testAcc
	returnedAccount := storageManager.ReadAccount("hid", []string{"hello", "env", "test"}, "realm")
	if diff := (&pretty.Config{IncludeUnexported: false}).Compare(testAcc, returnedAccount); diff != "" {
		t.Errorf("Returned account differs from expected account: -want/+got:\n %s", diff)
	}
	readAccount := storageManager.ReadAccount("this_should_break_it", []string{"hello", "env", "test"}, "realm")
	if readAccount != nil {
		t.Errorf("Returned account should be nil, instead it is %v", readAccount)
	}
}

func TestWriteAccount(t *testing.T) {
	storageManager := createDefaultStorageManager()
	testAcc := msalbase.NewAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")
	key := testAcc.CreateKey()
	err := storageManager.WriteAccount(testAcc)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if diff := (&pretty.Config{IncludeUnexported: false}).Compare(testAcc, storageManager.accounts[key]); diff != "" {
		t.Errorf("Added account differs from expected account: -want/+got:\n %s", diff)
	}
}

func TestReadAppMetadata(t *testing.T) {
	storageManager := createDefaultStorageManager()
	testAppMeta := createAppMetadata("fid", "cid", "env")
	storageManager.appMetadatas[testAppMeta.CreateKey()] = testAppMeta
	returnedAppMeta := storageManager.ReadAppMetadata([]string{"hello", "test", "env"}, "cid")
	if diff := (&pretty.Config{IncludeUnexported: false}).Compare(testAppMeta, returnedAppMeta); diff != "" {
		t.Errorf("Returned app metadata differs from expected app metadata: -want/+got:\n %s", diff)
	}
	readAppMeta := storageManager.ReadAppMetadata([]string{"hello", "test", "env"}, "break_this")
	if readAppMeta != nil {
		t.Errorf("Returned app metadata should be nil; instead it is %v", readAppMeta)
	}
}

func TestWriteAppMetadata(t *testing.T) {
	storageManager := createDefaultStorageManager()
	testAppMeta := createAppMetadata("fid", "cid", "env")
	key := testAppMeta.CreateKey()
	err := storageManager.WriteAppMetadata(testAppMeta)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if diff := (&pretty.Config{IncludeUnexported: false}).Compare(testAppMeta, storageManager.appMetadatas[key]); diff != "" {
		t.Errorf("Added app metadata differs from expected account: -want/+got:\n %s", diff)
	}
}

func TestReadIDToken(t *testing.T) {
	storageManager := createDefaultStorageManager()
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
	if diff := (&pretty.Config{IncludeUnexported: false}).Compare(testIDToken, returnedIDToken); diff != "" {
		t.Errorf("Returned ID token differs from expected ID token: -want/+got:\n %s", diff)
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
	storageManager := createDefaultStorageManager()
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
	if diff := (&pretty.Config{IncludeUnexported: false}).Compare(testIDToken, storageManager.idTokens[key]); diff != "" {
		t.Errorf("Added ID token differs from expected ID Token: -want/+got:\n %s", diff)
	}
}

func Test_defaultStorageManager_ReadRefreshToken(t *testing.T) {
	testRefreshTokenWithFID := createRefreshTokenCacheItem(
		"hid",
		"env",
		"cid",
		"secret",
		"fid",
	)
	testRefreshTokenWoFID := createRefreshTokenCacheItem(
		"hid",
		"env",
		"cid",
		"secret",
		"",
	)
	testRefreshTokenWoFIDAltCID := createRefreshTokenCacheItem(
		"hid",
		"env",
		"cid2",
		"secret",
		"",
	)
	type args struct {
		homeAccountID string
		envAliases    []string
		familyID      string
		clientID      string
	}
	tests := []struct {
		name string
		m    *defaultStorageManager
		args args
		want *refreshTokenCacheItem
	}{
		{
			name: "Token without fid, read with fid, cid, env, and hid",
			m: &defaultStorageManager{
				refreshTokens: map[string]*refreshTokenCacheItem{
					testRefreshTokenWoFID.CreateKey(): testRefreshTokenWoFID,
				},
			},
			args: args{
				homeAccountID: "hid",
				envAliases:    []string{"test", "env", "hello"},
				familyID:      "fid",
				clientID:      "cid",
			},
			want: testRefreshTokenWoFID,
		},
		{
			name: "Token without fid, read with cid, env, and hid",
			m: &defaultStorageManager{
				refreshTokens: map[string]*refreshTokenCacheItem{
					testRefreshTokenWoFID.CreateKey(): testRefreshTokenWoFID,
				},
			},
			args: args{
				homeAccountID: "hid",
				envAliases:    []string{"test", "env", "hello"},
				familyID:      "",
				clientID:      "cid",
			},
			want: testRefreshTokenWoFID,
		},
		{
			name: "Token without fid, verify CID is required",
			m: &defaultStorageManager{
				refreshTokens: map[string]*refreshTokenCacheItem{
					testRefreshTokenWoFID.CreateKey(): testRefreshTokenWoFID,
				},
			},
			args: args{
				homeAccountID: "hid",
				envAliases:    []string{"test", "env", "hello"},
				familyID:      "",
				clientID:      "",
			},
			want: nil,
		},
		{
			name: "Token without fid, Verify env is required",
			m: &defaultStorageManager{
				refreshTokens: map[string]*refreshTokenCacheItem{
					testRefreshTokenWoFID.CreateKey(): testRefreshTokenWoFID,
				},
			},
			args: args{
				homeAccountID: "hid",
				envAliases:    []string{},
				familyID:      "",
				clientID:      "",
			},
			want: nil,
		},
		{
			name: "Token with fid, read with fid, cid, env, and hid",
			m: &defaultStorageManager{
				refreshTokens: map[string]*refreshTokenCacheItem{
					testRefreshTokenWithFID.CreateKey(): testRefreshTokenWithFID,
				},
			},
			args: args{
				homeAccountID: "hid",
				envAliases:    []string{"test", "env", "hello"},
				familyID:      "fid",
				clientID:      "cid",
			},
			want: testRefreshTokenWithFID,
		},
		{
			name: "Token with fid, read with cid, env, and hid",
			m: &defaultStorageManager{
				refreshTokens: map[string]*refreshTokenCacheItem{
					testRefreshTokenWithFID.CreateKey(): testRefreshTokenWithFID,
				},
			},
			args: args{
				homeAccountID: "hid",
				envAliases:    []string{"test", "env", "hello"},
				familyID:      "",
				clientID:      "cid",
			},
			want: testRefreshTokenWithFID,
		},
		{
			name: "Token with fid, verify CID is not required", // match on hid, env, and has fid
			m: &defaultStorageManager{
				refreshTokens: map[string]*refreshTokenCacheItem{
					testRefreshTokenWithFID.CreateKey(): testRefreshTokenWithFID,
				},
			},
			args: args{
				homeAccountID: "hid",
				envAliases:    []string{"test", "env", "hello"},
				familyID:      "",
				clientID:      "",
			},
			want: testRefreshTokenWithFID,
		},
		{
			name: "Token with fid, Verify env is required",
			m: &defaultStorageManager{
				refreshTokens: map[string]*refreshTokenCacheItem{
					testRefreshTokenWithFID.CreateKey(): testRefreshTokenWithFID,
				},
			},
			args: args{
				homeAccountID: "hid",
				envAliases:    []string{},
				familyID:      "",
				clientID:      "",
			},
			want: nil,
		},
		{
			name: "Multiple items in cache, given a fid, item with fid will be returned",
			m: &defaultStorageManager{
				refreshTokens: map[string]*refreshTokenCacheItem{
					testRefreshTokenWoFID.CreateKey():       testRefreshTokenWoFID,
					testRefreshTokenWithFID.CreateKey():     testRefreshTokenWithFID,
					testRefreshTokenWoFIDAltCID.CreateKey(): testRefreshTokenWoFIDAltCID,
				},
			},
			args: args{
				homeAccountID: "hid",
				envAliases:    []string{},
				familyID:      "fid",
				clientID:      "cid",
			},
			want: nil,
		},
		// Cannot guarentee that without an alternate cid which token will be
		// returned deterministically when HID, CID, and env match.
		{
			name: "Multiple items in cache, without a fid and with alternate CID, token with alternate CID is returned",
			m: &defaultStorageManager{
				refreshTokens: map[string]*refreshTokenCacheItem{
					testRefreshTokenWoFID.CreateKey():       testRefreshTokenWoFID,
					testRefreshTokenWithFID.CreateKey():     testRefreshTokenWithFID,
					testRefreshTokenWoFIDAltCID.CreateKey(): testRefreshTokenWoFIDAltCID,
				},
			},
			args: args{
				homeAccountID: "hid",
				envAliases:    []string{},
				familyID:      "",
				clientID:      "cid2",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.m.ReadRefreshToken(tt.args.homeAccountID, tt.args.envAliases, tt.args.familyID, tt.args.clientID)
			if diff := (&pretty.Config{IncludeUnexported: false}).Compare(tt.want, got); diff != "" {
				t.Errorf("defaultStorageManager.ReadRefreshToken(): -want/+got:\n %s", diff)
			}
		})
	}
}

func TestWriteRefreshToken(t *testing.T) {
	storageManager := createDefaultStorageManager()
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
	if diff := (&pretty.Config{IncludeUnexported: false}).Compare(testRefreshToken, storageManager.refreshTokens[key]); diff != "" {
		t.Errorf("Added refresh token differs from expected refresh token: -want/+got:\n %s", diff)
	}
}

func TestStorageManagerSerialize(t *testing.T) {
	manager := createDefaultStorageManager()
	manager.accessTokens = map[string]*accessTokenCacheItem{
		"an-entry": {
			additionalFields: map[string]interface{}{"foo": "bar"},
		},
		"uid.utid-login.windows.net-accesstoken-my_client_id-contoso-s2 s1 s3": {
			Environment:                    defaultEnvironment,
			CredentialType:                 accessTokenCred,
			Secret:                         accessTokenSecret,
			Realm:                          defaultRealm,
			Scopes:                         defaultScopes,
			ClientID:                       defaultClientID,
			CachedAt:                       atCached,
			HomeAccountID:                  defaultHID,
			ExpiresOnUnixTimestamp:         atExpires,
			ExtendedExpiresOnUnixTimestamp: atExpires,
			additionalFields:               make(map[string]interface{}),
		},
	}
	manager.refreshTokens = map[string]*refreshTokenCacheItem{
		"uid.utid-login.windows.net-refreshtoken-my_client_id--s2 s1 s3": {
			Target:           defaultScopes,
			Environment:      defaultEnvironment,
			CredentialType:   rtCredType,
			Secret:           rtSecret,
			ClientID:         defaultClientID,
			HomeAccountID:    defaultHID,
			additionalFields: make(map[string]interface{}),
		},
	}
	manager.idTokens = map[string]*idTokenCacheItem{
		"uid.utid-login.windows.net-idtoken-my_client_id-contoso-": {
			Realm:            defaultRealm,
			Environment:      defaultEnvironment,
			CredentialType:   idCred,
			Secret:           idSecret,
			ClientID:         defaultClientID,
			HomeAccountID:    defaultHID,
			additionalFields: make(map[string]interface{}),
		},
	}
	manager.accounts = map[string]*msalbase.Account{
		"uid.utid-login.windows.net-contoso": {
			PreferredUsername: accUser,
			LocalAccountID:    accLID,
			Realm:             defaultRealm,
			Environment:       defaultEnvironment,
			HomeAccountID:     defaultHID,
			AuthorityType:     accAuth,
		},
	}
	manager.appMetadatas = map[string]*appMetadata{
		"appmetadata-login.windows.net-my_client_id": {
			Environment:      defaultEnvironment,
			FamilyID:         "",
			ClientID:         defaultClientID,
			additionalFields: make(map[string]interface{}),
		},
	}
	_, err := manager.Serialize()
	if err != nil {
		t.Errorf("Error should be nil; instead it is %v", err)
	}
}

func TestStorageManagerDeserialize(t *testing.T) {
	manager := createDefaultStorageManager()
	jsonFile, err := os.Open(testFile)
	testCache, err := ioutil.ReadAll(jsonFile)
	jsonFile.Close()
	err = manager.Deserialize(testCache)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	actualATSecret := manager.accessTokens["uid.utid-login.windows.net-accesstoken-my_client_id-contoso-s2 s1 s3"].Secret
	if diff := (&pretty.Config{IncludeUnexported: false}).Compare(accessTokenSecret, actualATSecret); diff != "" {
		t.Errorf("Expected access token secret differs from actual access token secret: -want/+got:\n %s", diff)
	}
	actualRTSecret := manager.refreshTokens["uid.utid-login.windows.net-refreshtoken-my_client_id--s2 s1 s3"].Secret
	if diff := (&pretty.Config{IncludeUnexported: false}).Compare(rtSecret, actualRTSecret); diff != "" {
		t.Errorf("Expected refresh tokens differ from actual refresh tokens: -want/+got:\n %s", diff)
	}
	actualIDSecret := manager.idTokens["uid.utid-login.windows.net-idtoken-my_client_id-contoso-"].Secret
	if diff := (&pretty.Config{IncludeUnexported: false}).Compare(idSecret, actualIDSecret); diff != "" {
		t.Errorf("Expected ID tokens differ from actual ID tokens: -want/+got:\n %s", diff)
	}
	actualUser := manager.accounts["uid.utid-login.windows.net-contoso"].PreferredUsername
	if diff := (&pretty.Config{IncludeUnexported: false}).Compare(accUser, actualUser); diff != "" {
		t.Errorf("Actual account username differs from expected account username: -want/+got:\n %s", diff)
	}
	if manager.appMetadatas["appmetadata-login.windows.net-my_client_id"].FamilyID != "" {
		t.Errorf("Expected app metadata family ID is nil, instead it is %s", manager.appMetadatas["appmetadata-login.windows.net-my_client_id"].FamilyID)
	}
}
