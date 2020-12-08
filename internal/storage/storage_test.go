// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package storage

import (
	"context"
	"io/ioutil"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
	"github.com/kylelemons/godebug/pretty"
)

const (
	testFile           = "test_serialized_cache.json"
	defaultEnvironment = "login.windows.net"
	defaultHID         = "uid.utid"
	defaultRealm       = "contoso"
	defaultScopes      = "s2 s1 s3"
	defaultClientID    = "my_client_id"
	accessTokenSecret  = "an access token"
	atCached           = "1000"
	atExpires          = "4600"
	rtSecret           = "a refresh token"
	idCred             = "IdToken"
	idSecret           = "header.eyJvaWQiOiAib2JqZWN0MTIzNCIsICJwcmVmZXJyZWRfdXNlcm5hbWUiOiAiSm9obiBEb2UiLCAic3ViIjogInN1YiJ9.signature"
	accUser            = "John Doe"
	accLID             = "object1234"
	accAuth            = string(msalbase.MSSTS)
)

var (
	accessTokenCred = msalbase.CredentialTypeAccessToken
	rtCredType      = msalbase.CredentialTypeRefreshToken
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

func TestGetAllAccounts(t *testing.T) {
	testAccOne := msalbase.NewAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")
	testAccTwo := msalbase.NewAccount("HID", "ENV", "REALM", "LID", msalbase.MSSTS, "USERNAME")
	cache := &CacheSerializationContract{
		Accounts: map[string]msalbase.Account{
			testAccOne.CreateKey(): testAccOne,
			testAccTwo.CreateKey(): testAccTwo,
		},
	}

	storageManager := New()
	storageManager.Update(cache)

	actualAccounts, err := storageManager.GetAllAccounts()
	if err != nil {
		panic(err)
	}
	// GetAllAccounts() is unstable in that the order can be reversed between calls.
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

	testAccOne := msalbase.NewAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")
	testAccTwo := msalbase.NewAccount("HID", "ENV", "REALM", "LID", msalbase.MSSTS, "USERNAME")
	cache := &CacheSerializationContract{
		Accounts: map[string]msalbase.Account{
			testAccOne.CreateKey(): testAccOne,
			testAccTwo.CreateKey(): testAccTwo,
		},
	}
	storageManager := New()
	storageManager.Update(cache)

	err := storageManager.DeleteAccounts("hid", []string{"hello", "env", "test"})
	if err != nil {
		t.Errorf("Error is supposed to be nil; instead it is %v", err)
	}
}

func TestReadAccessToken(t *testing.T) {
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
	cache := &CacheSerializationContract{
		AccessTokens: map[string]AccessTokenCacheItem{
			testAccessToken.CreateKey(): testAccessToken,
		},
	}
	storageManager := New()
	storageManager.Update(cache)

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
	storageManager := New()
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
		t.Fatalf("TestWriteAccessToken: got err == %s, want err == nil", err)
	}

	if diff := pretty.Compare(testAccessToken, storageManager.Contract().AccessTokens[key]); diff != "" {
		t.Errorf("TestWriteAccessToken: -want/+got:\n%s", diff)
	}
}

func TestReadAccount(t *testing.T) {
	testAcc := msalbase.NewAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")

	cache := &CacheSerializationContract{
		Accounts: map[string]msalbase.Account{
			testAcc.CreateKey(): testAcc,
		},
	}
	storageManager := New()
	storageManager.Update(cache)

	returnedAccount, err := storageManager.ReadAccount("hid", []string{"hello", "env", "test"}, "realm")
	if err != nil {
		t.Fatalf("TestReadAccount: got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAcc, returnedAccount); diff != "" {
		t.Errorf("TestReadAccount: -want/+got:\n%s", diff)
	}

	_, err = storageManager.ReadAccount("this_should_break_it", []string{"hello", "env", "test"}, "realm")
	if err == nil {
		t.Errorf("TestReadAccount: got err == nil, want err != nil")
	}
}

func TestWriteAccount(t *testing.T) {
	storageManager := New()
	testAcc := msalbase.NewAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")
	key := testAcc.CreateKey()
	err := storageManager.WriteAccount(testAcc)
	if err != nil {
		t.Fatalf("TestWriteAccount: got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAcc, storageManager.Contract().Accounts[key]); diff != "" {
		t.Errorf("TestWriteAccount: -want/+got:\n%s", diff)
	}
}

func TestReadAppMetadata(t *testing.T) {
	testAppMeta := CreateAppMetadata("fid", "cid", "env")

	cache := &CacheSerializationContract{
		AppMetadata: map[string]AppMetadata{
			testAppMeta.CreateKey(): testAppMeta,
		},
	}
	storageManager := New()
	storageManager.Update(cache)

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
	storageManager := New()
	testAppMeta := CreateAppMetadata("fid", "cid", "env")
	key := testAppMeta.CreateKey()
	err := storageManager.WriteAppMetadata(testAppMeta)
	if err != nil {
		t.Fatalf("TestWriteAppMetadata: got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAppMeta, storageManager.Contract().AppMetadata[key]); diff != "" {
		t.Errorf("TestWriteAppMetadata: -want/+got:\n%s", diff)
	}
}

func TestReadIDToken(t *testing.T) {
	testIDToken := CreateIDTokenCacheItem(
		"hid",
		"env",
		"realm",
		"cid",
		"secret",
	)
	cache := &CacheSerializationContract{
		IDTokens: map[string]IDTokenCacheItem{
			testIDToken.CreateKey(): testIDToken,
		},
	}
	storageManager := New()
	storageManager.Update(cache)

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
	storageManager := New()
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
		t.Fatalf("TestWriteIDToken: got err == %s, want err == nil", err)
	}

	if diff := pretty.Compare(testIDToken, storageManager.Contract().IDTokens[key]); diff != "" {
		t.Errorf("TestWriteIDToken: -want/+got:\n%s", diff)
	}
}

func TestDefaultStorageManagerReadRefreshToken(t *testing.T) {
	testRefreshTokenWithFID := CreateRefreshTokenCacheItem(
		"hid",
		"env",
		"cid",
		"secret",
		"fid",
	)
	testRefreshTokenWoFID := CreateRefreshTokenCacheItem(
		"hid",
		"env",
		"cid",
		"secret",
		"",
	)
	testRefreshTokenWoFIDAltCID := CreateRefreshTokenCacheItem(
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
		name     string
		contract *CacheSerializationContract
		args     args
		want     RefreshTokenCacheItem
		err      bool
	}{
		{
			name: "Token without fid, read with fid, cid, env, and hid",
			contract: &CacheSerializationContract{
				RefreshTokens: map[string]RefreshTokenCacheItem{
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
			contract: &CacheSerializationContract{
				RefreshTokens: map[string]RefreshTokenCacheItem{
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
			contract: &CacheSerializationContract{
				RefreshTokens: map[string]RefreshTokenCacheItem{
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
			contract: &CacheSerializationContract{
				RefreshTokens: map[string]RefreshTokenCacheItem{
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
			contract: &CacheSerializationContract{
				RefreshTokens: map[string]RefreshTokenCacheItem{
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
			contract: &CacheSerializationContract{
				RefreshTokens: map[string]RefreshTokenCacheItem{
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
			contract: &CacheSerializationContract{
				RefreshTokens: map[string]RefreshTokenCacheItem{
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
			contract: &CacheSerializationContract{
				RefreshTokens: map[string]RefreshTokenCacheItem{
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
			contract: &CacheSerializationContract{
				RefreshTokens: map[string]RefreshTokenCacheItem{
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
			contract: &CacheSerializationContract{
				RefreshTokens: map[string]RefreshTokenCacheItem{
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

	m := &Manager{}
	for _, test := range tests {
		m.Update(test.contract)

		got, err := m.ReadRefreshToken(test.args.homeAccountID, test.args.envAliases, test.args.familyID, test.args.clientID)
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
	storageManager := New()
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
	if !reflect.DeepEqual(storageManager.Contract().RefreshTokens[key], testRefreshToken) {
		t.Errorf("Added refresh token %v differs from expected refresh token %v",
			storageManager.Contract().RefreshTokens[key],
			testRefreshToken)
	}
}

func TestStorageManagerSerialize(t *testing.T) {
	contract := &CacheSerializationContract{
		AccessTokens: map[string]AccessTokenCacheItem{
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
		},
		RefreshTokens: map[string]RefreshTokenCacheItem{
			"uid.utid-login.windows.net-refreshtoken-my_client_id--s2 s1 s3": {
				Target:         defaultScopes,
				Environment:    defaultEnvironment,
				CredentialType: rtCredType,
				Secret:         rtSecret,
				ClientID:       defaultClientID,
				HomeAccountID:  defaultHID,
			},
		},
		IDTokens: map[string]IDTokenCacheItem{
			"uid.utid-login.windows.net-idtoken-my_client_id-contoso-": {
				Realm:          defaultRealm,
				Environment:    defaultEnvironment,
				CredentialType: idCred,
				Secret:         idSecret,
				ClientID:       defaultClientID,
				HomeAccountID:  defaultHID,
			},
		},
		Accounts: map[string]msalbase.Account{
			"uid.utid-login.windows.net-contoso": {
				PreferredUsername: accUser,
				LocalAccountID:    accLID,
				Realm:             defaultRealm,
				Environment:       defaultEnvironment,
				HomeAccountID:     defaultHID,
				AuthorityType:     accAuth,
			},
		},
		AppMetadata: map[string]AppMetadata{
			"AppMetadata-login.windows.net-my_client_id": {
				Environment: defaultEnvironment,
				FamilyID:    "",
				ClientID:    defaultClientID,
			},
		},
	}

	manager := New()
	manager.Update(contract)

	_, err := manager.Serialize()
	if err != nil {
		t.Errorf("Error should be nil; instead it is %v", err)
	}
}

func TestStorageManagerDeserialize(t *testing.T) {
	manager := New()
	b, err := ioutil.ReadFile(testFile)
	if err != nil {
		panic(err)
	}

	err = manager.Deserialize(b)
	if err != nil {
		t.Fatalf("TestStorageManagerDeserialize(Deserialize): got err == %s, want err == nil", err)
	}

	actualAccessTokenSecret := manager.Contract().AccessTokens["uid.utid-login.windows.net-accesstoken-my_client_id-contoso-s2 s1 s3"].Secret
	if accessTokenSecret != actualAccessTokenSecret {
		t.Errorf("TestStorageManagerDeserialize(access token secret):got %q, want %q", actualAccessTokenSecret, accessTokenSecret)
	}

	actualRTSecret := manager.Contract().RefreshTokens["uid.utid-login.windows.net-refreshtoken-my_client_id--s2 s1 s3"].Secret
	if diff := pretty.Compare(rtSecret, actualRTSecret); diff != "" {
		t.Errorf("TestStorageManagerDeserialize(refresh token secret): -want/+got:\n%s", diff)
	}

	actualIDSecret := manager.Contract().IDTokens["uid.utid-login.windows.net-idtoken-my_client_id-contoso-"].Secret
	if diff := pretty.Compare(idSecret, actualIDSecret); diff != "" {
		t.Errorf("TestStorageManagerDeserialize(id secret): -want/+got:\n%s", diff)
	}
	actualUser := manager.Contract().Accounts["uid.utid-login.windows.net-contoso"].PreferredUsername
	if diff := pretty.Compare(actualUser, accUser); diff != "" {
		t.Errorf("TestStorageManagerDeserialize(actula user): -want/+got:\n%s", diff)
	}
	if manager.Contract().AppMetadata["AppMetadata-login.windows.net-my_client_id"].FamilyID != "" {
		t.Errorf("TestStorageManagerDeserialize(app metadata family id): got %q, want empty string", manager.Contract().AppMetadata["AppMetadata-login.windows.net-my_client_id"].FamilyID)
	}
}

func TestIsAccessTokenValid(t *testing.T) {
	cachedAt := time.Now().Unix()
	badCachedAt := time.Now().Unix() + 500
	expiresOn := time.Now().Unix() + 1000
	badExpiresOn := time.Now().Unix() + 200
	extended := time.Now().Unix()

	tests := []struct {
		desc  string
		token AccessTokenCacheItem
		err   bool
	}{
		{
			desc:  "Success",
			token: createAccessTokenCacheItem("hid", "env", "realm", "cid", cachedAt, expiresOn, extended, "openid", "secret"),
		},
		{
			desc:  "ExpiresOnUnixTimestamp has expired",
			token: createAccessTokenCacheItem("hid", "env", "realm", "cid", cachedAt, badExpiresOn, extended, "openid", "secret"),
			err:   true,
		},
		{
			desc:  "Success",
			token: createAccessTokenCacheItem("hid", "env", "realm", "cid", badCachedAt, expiresOn, extended, "openid", "secret"),
			err:   true,
		},
	}

	for _, test := range tests {
		err := test.token.Validate()
		switch {
		case err == nil && test.err:
			t.Errorf("TestIsAccessTokenValid(%s): got err == nil, want err != nil", test.desc)
		case err != nil && !test.err:
			t.Errorf("TestIsAccessTokenValid(%s): got err == %s, want err == nil", test.desc, err)
		}
	}
}

func TestTryReadCache(t *testing.T) {
	mockWebRequestManager := new(requests.MockWebRequestManager)

	accessTokenCacheItem := createAccessTokenCacheItem(
		"hid",
		"env",
		"realm",
		"cid",
		time.Now().Unix(),
		time.Now().Unix()+1000,
		time.Now().Unix(),
		"openid profile",
		"secret",
	)
	testIDToken := CreateIDTokenCacheItem(
		"hid",
		"env",
		"realm",
		"cid",
		"secret",
	)
	testAppMeta := CreateAppMetadata("fid", "cid", "env")
	testRefreshToken := CreateRefreshTokenCacheItem(
		"hid",
		"env",
		"cid",
		"secret",
		"fid",
	)
	testAccount := msalbase.NewAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")

	contract := &CacheSerializationContract{
		RefreshTokens: map[string]RefreshTokenCacheItem{
			testRefreshToken.CreateKey(): testRefreshToken,
		},
		Accounts: map[string]msalbase.Account{
			testAccount.CreateKey(): testAccount,
		},
		AppMetadata: map[string]AppMetadata{
			testAppMeta.CreateKey(): testAppMeta,
		},
		IDTokens: map[string]IDTokenCacheItem{
			testIDToken.CreateKey(): testIDToken,
		},
		AccessTokens: map[string]AccessTokenCacheItem{
			accessTokenCacheItem.CreateKey(): accessTokenCacheItem,
		},
	}
	manager := New()
	manager.Update(contract)

	authInfo := msalbase.AuthorityInfo{
		Host:   "env",
		Tenant: "realm",
	}
	authParameters := msalbase.AuthParametersInternal{
		HomeaccountID: "hid",
		AuthorityInfo: authInfo,
		ClientID:      "cid",
		Scopes:        []string{"openid", "profile"},
	}
	metadata1 := requests.InstanceDiscoveryMetadata{
		Aliases: []string{"env", "alias2"},
	}
	metadata2 := requests.InstanceDiscoveryMetadata{
		Aliases: []string{"alias3", "alias4"},
	}
	metadata := []requests.InstanceDiscoveryMetadata{metadata1, metadata2}
	mockInstDiscResponse := requests.InstanceDiscoveryResponse{
		TenantDiscoveryEndpoint: "tenant",
		Metadata:                metadata,
	}
	mockWebRequestManager.On("GetAadinstanceDiscoveryResponse", authInfo).Return(mockInstDiscResponse, nil)

	want := msalbase.CreateStorageTokenResponse(accessTokenCacheItem, testRefreshToken, testIDToken, testAccount)
	got, err := manager.TryReadCache(context.Background(), authParameters, mockWebRequestManager)
	if err != nil {
		t.Fatalf("TestTryReadCache: got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestTryReadCache: -want/+got:\n%s", diff)
	}
}

func TestCacheTokenResponse(t *testing.T) {
	cacheManager := New()
	clientInfo := msalbase.ClientInfoJSONPayload{
		UID:  "testUID",
		Utid: "testUtid",
	}
	idToken := msalbase.IDToken{
		RawToken:          "idToken",
		Oid:               "lid",
		PreferredUsername: "username",
	}
	expiresOn := time.Unix(time.Now().Unix()+1000, 0).UTC()
	tokenResponse := msalbase.TokenResponse{
		AccessToken:   "accessToken",
		RefreshToken:  "refreshToken",
		IDToken:       idToken,
		FamilyID:      "fid",
		ClientInfo:    clientInfo,
		GrantedScopes: []string{"openid", "profile"},
		ExpiresOn:     expiresOn,
		ExtExpiresOn:  time.Now(),
	}
	authInfo := msalbase.AuthorityInfo{Host: "env", Tenant: "realm", AuthorityType: msalbase.MSSTS}
	authParams := msalbase.AuthParametersInternal{
		AuthorityInfo: authInfo,
		ClientID:      "cid",
	}
	testRefreshToken := CreateRefreshTokenCacheItem(
		"testUID.testUtid",
		"env",
		"cid",
		"refreshToken",
		"fid",
	)

	AccessTokenCacheItem := createAccessTokenCacheItem(
		"testUID.testUtid",
		"env",
		"realm",
		"cid",
		time.Now().Unix(),
		time.Now().Unix()+1000,
		time.Now().Unix(),
		"openid profile",
		"accessToken",
	)

	testIDToken := CreateIDTokenCacheItem(
		"testUID.testUtid",
		"env",
		"realm",
		"cid",
		"idToken",
	)

	testAccount := msalbase.NewAccount("testUID.testUtid", "env", "realm", "lid", msalbase.MSSTS, "username")
	testAppMeta := CreateAppMetadata("fid", "cid", "env")

	actualAccount, err := cacheManager.CacheTokenResponse(authParams, tokenResponse)
	if err != nil {
		t.Errorf("Error should be nil; instead, it is %v", err)
	}
	if !reflect.DeepEqual(actualAccount, testAccount) {
		t.Errorf("Actual account %+v differs from expected account %+v", actualAccount, testAccount)
	}

	gotRefresh, ok := cacheManager.Contract().RefreshTokens[testRefreshToken.CreateKey()]
	if !ok {
		t.Fatalf("TestCacheTokenResponse(refresh token): refresh token was not written as expected")
	}
	if diff := pretty.Compare(testRefreshToken, gotRefresh); diff != "" {
		t.Fatalf("TestCacheTokenResponse(refresh token): -want/+got\n%s", diff)
	}

	gotAccess, ok := cacheManager.Contract().AccessTokens[AccessTokenCacheItem.CreateKey()]
	if !ok {
		t.Fatalf("TestCacheTokenResponse(access token): access token was not written as expected")
	}
	if diff := pretty.Compare(AccessTokenCacheItem, gotAccess); diff != "" {
		t.Fatalf("TestCacheTokenResponse(access token): -want/+got\n%s", diff)
	}

	gotToken, ok := cacheManager.Contract().IDTokens[testIDToken.CreateKey()]
	if !ok {
		t.Fatalf("TestCacheTokenResponse(id token): id token was not written as expected")
	}
	if diff := pretty.Compare(testIDToken, gotToken); diff != "" {
		t.Fatalf("TestCacheTokenResponse(id token): -want/+got\n%s", diff)
	}

	gotAccount, ok := cacheManager.Contract().Accounts[testAccount.CreateKey()]
	if !ok {
		t.Fatalf("TestCacheTokenResponse(account): account was not written as expected")
	}
	if diff := pretty.Compare(testAccount, gotAccount); diff != "" {
		t.Fatalf("TestCacheTokenResponse(account): -want/+got\n%s", diff)
	}

	gotMeta, ok := cacheManager.Contract().AppMetadata[testAppMeta.CreateKey()]
	if !ok {
		t.Fatalf("TestCacheTokenResponse(app metadata): metadata was not written as expected")
	}
	if diff := pretty.Compare(testAppMeta, gotMeta); diff != "" {
		t.Fatalf("TestCacheTokenResponse(app metadata): -want/+got\n%s", diff)
	}
}
