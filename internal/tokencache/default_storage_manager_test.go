// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"io/ioutil"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/kylelemons/godebug/pretty"
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
		t.Fatalf("Scopes %v and %v are supposed to be the same", scopesOne, scopesTwo)
	}
	errorScopes := "openid user.read hello"
	if isMatchingScopes(scopesOne, errorScopes) {
		t.Fatalf("Scopes %v and %v are not supposed to be the same", scopesOne, errorScopes)
	}
}

func TestReadAllAccounts(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  make(map[string]accessTokenCacheItem),
		refreshTokens: make(map[string]refreshTokenCacheItem),
		idTokens:      make(map[string]idTokenCacheItem),
		accounts:      make(map[string]msalbase.Account),
		appMetadatas:  make(map[string]appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
	testAccOne := msalbase.NewAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")
	testAccTwo := msalbase.NewAccount("HID", "ENV", "REALM", "LID", msalbase.MSSTS, "USERNAME")
	storageManager.accounts[testAccOne.CreateKey()] = testAccOne
	storageManager.accounts[testAccTwo.CreateKey()] = testAccTwo
	actualAccounts, err := storageManager.ReadAllAccounts()
	if err != nil {
		panic(err)
	}
	// ReadAllAccounts() is unstable in that the order can be reversed between calls.
	// This fixes that.
	sort.Slice(
		actualAccounts,
		func(i, j int) bool {
			return actualAccounts[i].HomeAccountID > actualAccounts[j].HomeAccountID
		},
	)

	expectedAccounts := []msalbase.Account{testAccOne, testAccTwo}
	if diff := pretty.Compare(expectedAccounts, actualAccounts); diff != "" {
		t.Errorf("Actual accounts differ from expected accounts: -want/+got:\n%s", diff)
	}
}

func TestDeleteAccounts(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  make(map[string]accessTokenCacheItem),
		refreshTokens: make(map[string]refreshTokenCacheItem),
		idTokens:      make(map[string]idTokenCacheItem),
		accounts:      make(map[string]msalbase.Account),
		appMetadatas:  make(map[string]appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
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
	storageManager := &defaultStorageManager{
		accessTokens:  map[string]accessTokenCacheItem{},
		refreshTokens: map[string]refreshTokenCacheItem{},
		idTokens:      map[string]idTokenCacheItem{},
		accounts:      map[string]msalbase.Account{},
		appMetadatas:  map[string]appMetadata{},
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
	retAccessToken, err := storageManager.ReadAccessToken(
		"hid",
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
		[]string{"user.read", "openid"},
	)
	if err != nil {
		t.Errorf("ReadAccessToken(): got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAccessToken, retAccessToken); diff != "" {
		t.Fatalf("Returned access token is not the same as expected access token: -want/+got:\n%s", diff)
	}
	_, err = storageManager.ReadAccessToken(
		"this_should_break_it",
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
		[]string{"user.read", "openid"},
	)
	if err == nil {
		t.Errorf("ReadAccessToken(): got err == nil, want err != nil")
	}
}

func TestWriteAccessToken(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  map[string]accessTokenCacheItem{},
		refreshTokens: map[string]refreshTokenCacheItem{},
		idTokens:      map[string]idTokenCacheItem{},
		accounts:      map[string]msalbase.Account{},
		appMetadatas:  map[string]appMetadata{},
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
		accessTokens:  map[string]accessTokenCacheItem{},
		refreshTokens: map[string]refreshTokenCacheItem{},
		idTokens:      map[string]idTokenCacheItem{},
		accounts:      map[string]msalbase.Account{},
		appMetadatas:  map[string]appMetadata{},
		cacheContract: createCacheSerializationContract(),
	}
	testAcc := msalbase.NewAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")
	storageManager.accounts[testAcc.CreateKey()] = testAcc
	returnedAccount, err := storageManager.ReadAccount("hid", []string{"hello", "env", "test"}, "realm")
	if err != nil {
		t.Fatalf("ReadAccount: got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAcc, returnedAccount); diff != "" {
		t.Errorf("Returned account differs from expected account: -want/+got:\n%s", diff)
	}

	_, err = storageManager.ReadAccount("this_should_break_it", []string{"hello", "env", "test"}, "realm")
	if err == nil {
		t.Errorf("Returned account: got err == nil, want err != nil")
	}
}

func TestWriteAccount(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  map[string]accessTokenCacheItem{},
		refreshTokens: map[string]refreshTokenCacheItem{},
		idTokens:      map[string]idTokenCacheItem{},
		accounts:      map[string]msalbase.Account{},
		appMetadatas:  map[string]appMetadata{},
		cacheContract: createCacheSerializationContract(),
	}
	testAcc := msalbase.NewAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")
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
		accessTokens:  map[string]accessTokenCacheItem{},
		refreshTokens: map[string]refreshTokenCacheItem{},
		idTokens:      map[string]idTokenCacheItem{},
		accounts:      map[string]msalbase.Account{},
		appMetadatas:  map[string]appMetadata{},
		cacheContract: createCacheSerializationContract(),
	}
	testAppMeta := createAppMetadata("fid", "cid", "env")
	storageManager.appMetadatas[testAppMeta.CreateKey()] = testAppMeta
	returnedAppMeta, err := storageManager.ReadAppMetadata([]string{"hello", "test", "env"}, "cid")
	if err != nil {
		t.Fatalf("TestReadAppMetadata(ReadAppMetadata): got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAppMeta, returnedAppMeta); diff != "" {
		t.Fatalf("TestReadAppMetadata(ReadAppMetadata): -want/+got:\n%s", diff)
	}

	_, err = storageManager.ReadAppMetadata([]string{"hello", "test", "env"}, "break_this")
	if err == nil {
		t.Fatalf("TestReadAppMetadata(bad ReadAppMetadata): got err == nil, want err != nil")
	}
}

func TestWriteAppMetadata(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  map[string]accessTokenCacheItem{},
		refreshTokens: map[string]refreshTokenCacheItem{},
		idTokens:      map[string]idTokenCacheItem{},
		accounts:      map[string]msalbase.Account{},
		appMetadatas:  map[string]appMetadata{},
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
		accessTokens:  map[string]accessTokenCacheItem{},
		refreshTokens: map[string]refreshTokenCacheItem{},
		idTokens:      map[string]idTokenCacheItem{},
		accounts:      map[string]msalbase.Account{},
		appMetadatas:  map[string]appMetadata{},
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
	returnedIDToken, err := storageManager.ReadIDToken(
		"hid",
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
	)
	if err != nil {
		panic(err)
	}

	if diff := pretty.Compare(testIDToken, returnedIDToken); diff != "" {
		t.Fatalf("TestReadIDToken(good token): -want/+got:\n%s", diff)
	}

	_, err = storageManager.ReadIDToken(
		"this_should_break_it",
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
	)
	if err == nil {
		t.Errorf("TestReadIDToken(bad token): got err == nil, want err != nil")
	}
}

func TestWriteIDToken(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  map[string]accessTokenCacheItem{},
		refreshTokens: map[string]refreshTokenCacheItem{},
		idTokens:      map[string]idTokenCacheItem{},
		accounts:      map[string]msalbase.Account{},
		appMetadatas:  map[string]appMetadata{},
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

func TestDefaultStorageManagerReadRefreshToken(t *testing.T) {
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
		want refreshTokenCacheItem
		err  bool
	}{
		{
			name: "Token without fid, read with fid, cid, env, and hid",
			m: &defaultStorageManager{
				refreshTokens: map[string]refreshTokenCacheItem{
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
				refreshTokens: map[string]refreshTokenCacheItem{
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
				refreshTokens: map[string]refreshTokenCacheItem{
					testRefreshTokenWoFID.CreateKey(): testRefreshTokenWoFID,
				},
			},
			args: args{
				homeAccountID: "hid",
				envAliases:    []string{"test", "env", "hello"},
				familyID:      "",
				clientID:      "",
			},
			err: true,
		},
		{
			name: "Token without fid, Verify env is required",
			m: &defaultStorageManager{
				refreshTokens: map[string]refreshTokenCacheItem{
					testRefreshTokenWoFID.CreateKey(): testRefreshTokenWoFID,
				},
			},
			args: args{
				homeAccountID: "hid",
				envAliases:    []string{},
				familyID:      "",
				clientID:      "",
			},
			err: true,
		},
		{
			name: "Token without fid, read with fid, cid, env, and hid",
			m: &defaultStorageManager{
				refreshTokens: map[string]refreshTokenCacheItem{
					testRefreshTokenWoFID.CreateKey(): testRefreshTokenWithFID,
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
				refreshTokens: map[string]refreshTokenCacheItem{
					testRefreshTokenWoFID.CreateKey(): testRefreshTokenWithFID,
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
				refreshTokens: map[string]refreshTokenCacheItem{
					testRefreshTokenWoFID.CreateKey(): testRefreshTokenWithFID,
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
				refreshTokens: map[string]refreshTokenCacheItem{
					testRefreshTokenWoFID.CreateKey(): testRefreshTokenWithFID,
				},
			},
			args: args{
				homeAccountID: "hid",
				envAliases:    []string{},
				familyID:      "",
				clientID:      "",
			},
			err: true,
		},
		{
			name: "Multiple items in cache, given a fid, item with fid will be returned",
			m: &defaultStorageManager{
				refreshTokens: map[string]refreshTokenCacheItem{
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
			err: true,
		},
		// Cannot guarentee that without an alternate cid which token will be
		// returned deterministically when HID, CID, and env match.
		{
			name: "Multiple items in cache, without a fid and with alternate CID, token with alternate CID is returned",
			m: &defaultStorageManager{
				refreshTokens: map[string]refreshTokenCacheItem{
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
			err: true,
		},
	}
	for _, test := range tests {
		got, err := test.m.ReadRefreshToken(test.args.homeAccountID, test.args.envAliases, test.args.familyID, test.args.clientID)
		switch {
		case test.err && err == nil:
			t.Errorf("TestDefaultStorageManagerReadRefreshToken(%s): got err == nil, want err != nil", test.name)
			continue
		case !test.err && err != nil:
			t.Errorf("TestDefaultStorageManagerReadRefreshToken(%s): got err == %s, want err == nil", test.name, err)
			continue
		case err != nil:
			continue
		}
		if diff := pretty.Compare(test.want, got); diff != "" {
			t.Errorf("TestDefaultStorageManagerReadRefreshToken(%s): -want/+got:\n%s", test.name, diff)
		}
	}
}

func TestWriteRefreshToken(t *testing.T) {
	storageManager := &defaultStorageManager{
		accessTokens:  make(map[string]accessTokenCacheItem),
		refreshTokens: make(map[string]refreshTokenCacheItem),
		idTokens:      make(map[string]idTokenCacheItem),
		accounts:      make(map[string]msalbase.Account),
		appMetadatas:  make(map[string]appMetadata),
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
		accessTokens:  make(map[string]accessTokenCacheItem),
		refreshTokens: make(map[string]refreshTokenCacheItem),
		idTokens:      make(map[string]idTokenCacheItem),
		accounts:      make(map[string]msalbase.Account),
		appMetadatas:  make(map[string]appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
	manager.accessTokens = map[string]accessTokenCacheItem{
		"an-entry": {
			AdditionalFields: map[string]interface{}{
				"foo": "bar",
			},
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
		},
	}
	manager.refreshTokens = map[string]refreshTokenCacheItem{
		"uid.utid-login.windows.net-refreshtoken-my_client_id--s2 s1 s3": {
			Target:         defaultScopes,
			Environment:    defaultEnvironment,
			CredentialType: rtCredType,
			Secret:         rtSecret,
			ClientID:       defaultClientID,
			HomeAccountID:  defaultHID,
		},
	}
	manager.idTokens = map[string]idTokenCacheItem{
		"uid.utid-login.windows.net-idtoken-my_client_id-contoso-": {
			Realm:          defaultRealm,
			Environment:    defaultEnvironment,
			CredentialType: idCred,
			Secret:         idSecret,
			ClientID:       defaultClientID,
			HomeAccountID:  defaultHID,
		},
	}
	manager.accounts = map[string]msalbase.Account{
		"uid.utid-login.windows.net-contoso": {
			PreferredUsername: accUser,
			LocalAccountID:    accLID,
			Realm:             defaultRealm,
			Environment:       defaultEnvironment,
			HomeAccountID:     defaultHID,
			AuthorityType:     accAuth,
		},
	}
	manager.appMetadatas = map[string]appMetadata{
		"appmetadata-login.windows.net-my_client_id": {
			Environment: defaultEnvironment,
			FamilyID:    "",
			ClientID:    defaultClientID,
		},
	}
	_, err := manager.Serialize()
	if err != nil {
		t.Errorf("Error should be nil; instead it is %v", err)
	}
}

func TestStorageManagerDeserialize(t *testing.T) {
	manager := &defaultStorageManager{
		accessTokens:  make(map[string]accessTokenCacheItem),
		refreshTokens: make(map[string]refreshTokenCacheItem),
		idTokens:      make(map[string]idTokenCacheItem),
		accounts:      make(map[string]msalbase.Account),
		appMetadatas:  make(map[string]appMetadata),
		cacheContract: createCacheSerializationContract(),
	}
	jsonFile, err := os.Open(testFile)
	testCache, err := ioutil.ReadAll(jsonFile)
	jsonFile.Close()
	err = manager.Deserialize(testCache)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	actualATSecret := manager.accessTokens["uid.utid-login.windows.net-accesstoken-my_client_id-contoso-s2 s1 s3"].Secret
	if !reflect.DeepEqual(accessTokenSecret, actualATSecret) {
		t.Errorf("Expected access token secret %+v differs from actual access token secret %+v", accessTokenSecret, actualATSecret)
	}
	actualRTSecret := manager.refreshTokens["uid.utid-login.windows.net-refreshtoken-my_client_id--s2 s1 s3"].Secret
	if !reflect.DeepEqual(rtSecret, actualRTSecret) {
		t.Errorf("Expected refresh tokens %+v differ from actual refresh tokens %+v", rtSecret, actualRTSecret)
	}
	actualIDSecret := manager.idTokens["uid.utid-login.windows.net-idtoken-my_client_id-contoso-"].Secret
	if !reflect.DeepEqual(idSecret, actualIDSecret) {
		t.Errorf("Expected ID tokens %+v differ from actual ID tokens %+v", idSecret, actualIDSecret)
	}
	actualUser := manager.accounts["uid.utid-login.windows.net-contoso"].PreferredUsername
	if !reflect.DeepEqual(actualUser, accUser) {
		t.Errorf("Actual account username %+s differs from expected account username %+v", actualUser, accUser)
	}
	if manager.appMetadatas["appmetadata-login.windows.net-my_client_id"].FamilyID != "" {
		t.Errorf("Expected app metadata family ID is nil, instead it is %s", manager.appMetadatas["appmetadata-login.windows.net-my_client_id"].FamilyID)
	}
}
