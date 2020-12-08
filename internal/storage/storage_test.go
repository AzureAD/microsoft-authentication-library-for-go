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
	cache := &Contract{
		Accounts: map[string]msalbase.Account{
			testAccOne.Key(): testAccOne,
			testAccTwo.Key(): testAccTwo,
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
	cache := &Contract{
		Accounts: map[string]msalbase.Account{
			testAccOne.Key(): testAccOne,
			testAccTwo.Key(): testAccTwo,
		},
	}
	storageManager := New()
	storageManager.Update(cache)

	err := storageManager.deleteAccounts("hid", []string{"hello", "env", "test"})
	if err != nil {
		t.Errorf("Error is supposed to be nil; instead it is %v", err)
	}
}

func TestReadAccessToken(t *testing.T) {
	testAccessToken := NewAccessToken(
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
	cache := &Contract{
		AccessTokens: map[string]AccessToken{
			testAccessToken.Key(): testAccessToken,
		},
	}
	storageManager := New()
	storageManager.Update(cache)

	retAccessToken, err := storageManager.readAccessToken(
		"hid",
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
		[]string{"user.read", "openid"},
	)
	if err != nil {
		t.Errorf("readAccessToken(): got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAccessToken, retAccessToken); diff != "" {
		t.Fatalf("Returned access token is not the same as expected access token: -want/+got:\n%s", diff)
	}
	_, err = storageManager.readAccessToken(
		"this_should_break_it",
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
		[]string{"user.read", "openid"},
	)
	if err == nil {
		t.Errorf("readAccessToken(): got err == nil, want err != nil")
	}
}

func TestWriteAccessToken(t *testing.T) {
	storageManager := New()
	testAccessToken := NewAccessToken(
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

	key := testAccessToken.Key()
	err := storageManager.writeAccessToken(testAccessToken)
	if err != nil {
		t.Fatalf("TestwriteAccessToken: got err == %s, want err == nil", err)
	}

	if diff := pretty.Compare(testAccessToken, storageManager.Contract().AccessTokens[key]); diff != "" {
		t.Errorf("TestwriteAccessToken: -want/+got:\n%s", diff)
	}
}

func TestReadAccount(t *testing.T) {
	testAcc := msalbase.NewAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")

	cache := &Contract{
		Accounts: map[string]msalbase.Account{
			testAcc.Key(): testAcc,
		},
	}
	storageManager := New()
	storageManager.Update(cache)

	returnedAccount, err := storageManager.readAccount("hid", []string{"hello", "env", "test"}, "realm")
	if err != nil {
		t.Fatalf("TestreadAccount: got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAcc, returnedAccount); diff != "" {
		t.Errorf("TestreadAccount: -want/+got:\n%s", diff)
	}

	_, err = storageManager.readAccount("this_should_break_it", []string{"hello", "env", "test"}, "realm")
	if err == nil {
		t.Errorf("TestreadAccount: got err == nil, want err != nil")
	}
}

func TestWriteAccount(t *testing.T) {
	storageManager := New()
	testAcc := msalbase.NewAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")

	key := testAcc.Key()
	err := storageManager.writeAccount(testAcc)
	if err != nil {
		t.Fatalf("TestwriteAccount: got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAcc, storageManager.Contract().Accounts[key]); diff != "" {
		t.Errorf("TestwriteAccount: -want/+got:\n%s", diff)
	}
}

func TestReadAppMetaData(t *testing.T) {
	testAppMeta := NewAppMetaData("fid", "cid", "env")

	cache := &Contract{
		AppMetaData: map[string]AppMetaData{
			testAppMeta.Key(): testAppMeta,
		},
	}
	storageManager := New()
	storageManager.Update(cache)

	returnedAppMeta, err := storageManager.readAppMetaData([]string{"hello", "test", "env"}, "cid")
	if err != nil {
		t.Fatalf("TestreadAppMetaData(readAppMetaData): got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAppMeta, returnedAppMeta); diff != "" {
		t.Fatalf("TestreadAppMetaData(readAppMetaData): -want/+got:\n%s", diff)
	}

	_, err = storageManager.readAppMetaData([]string{"hello", "test", "env"}, "break_this")
	if err == nil {
		t.Fatalf("TestreadAppMetaData(bad readAppMetaData): got err == nil, want err != nil")
	}
}

func TestWriteAppMetaData(t *testing.T) {
	storageManager := New()

	testAppMeta := NewAppMetaData("fid", "cid", "env")
	key := testAppMeta.Key()
	err := storageManager.writeAppMetaData(testAppMeta)
	if err != nil {
		t.Fatalf("TestwriteAppMetaData: got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAppMeta, storageManager.Contract().AppMetaData[key]); diff != "" {
		t.Errorf("TestwriteAppMetaData: -want/+got:\n%s", diff)
	}
}

func TestReadIDToken(t *testing.T) {
	testIDToken := NewIDToken(
		"hid",
		"env",
		"realm",
		"cid",
		"secret",
	)
	cache := &Contract{
		IDTokens: map[string]IDToken{
			testIDToken.Key(): testIDToken,
		},
	}
	storageManager := New()
	storageManager.Update(cache)

	returnedIDToken, err := storageManager.readIDToken(
		"hid",
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
	)
	if err != nil {
		panic(err)
	}

	if diff := pretty.Compare(testIDToken, returnedIDToken); diff != "" {
		t.Fatalf("TestreadIDToken(good token): -want/+got:\n%s", diff)
	}

	_, err = storageManager.readIDToken(
		"this_should_break_it",
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
	)
	if err == nil {
		t.Errorf("TestreadIDToken(bad token): got err == nil, want err != nil")
	}
}

func TestWriteIDToken(t *testing.T) {
	storageManager := New()
	testIDToken := NewIDToken(
		"hid",
		"env",
		"realm",
		"cid",
		"secret",
	)

	key := testIDToken.Key()

	err := storageManager.writeIDToken(testIDToken)
	if err != nil {
		t.Fatalf("TestwriteIDToken: got err == %s, want err == nil", err)
	}

	if diff := pretty.Compare(testIDToken, storageManager.Contract().IDTokens[key]); diff != "" {
		t.Errorf("TestwriteIDToken: -want/+got:\n%s", diff)
	}
}

func TestDefaultStorageManagerreadRefreshToken(t *testing.T) {
	testRefreshTokenWithFID := NewRefreshToken(

		"hid",
		"env",
		"cid",
		"secret",
		"fid",
	)
	testRefreshTokenWoFID := NewRefreshToken(
		"hid",
		"env",
		"cid",
		"secret",
		"",
	)
	testRefreshTokenWoFIDAltCID := NewRefreshToken(
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
		contract *Contract
		args     args
		want     RefreshToken
		err      bool
	}{
		{
			name: "Token without fid, read with fid, cid, env, and hid",
			contract: &Contract{
				RefreshTokens: map[string]RefreshToken{
					testRefreshTokenWoFID.Key(): testRefreshTokenWoFID,
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
			contract: &Contract{
				RefreshTokens: map[string]RefreshToken{
					testRefreshTokenWoFID.Key(): testRefreshTokenWoFID,
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
			contract: &Contract{
				RefreshTokens: map[string]RefreshToken{
					testRefreshTokenWoFID.Key(): testRefreshTokenWoFID,
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
			contract: &Contract{
				RefreshTokens: map[string]RefreshToken{
					testRefreshTokenWoFID.Key(): testRefreshTokenWoFID,
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
			contract: &Contract{
				RefreshTokens: map[string]RefreshToken{
					testRefreshTokenWoFID.Key(): testRefreshTokenWithFID,
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
			contract: &Contract{
				RefreshTokens: map[string]RefreshToken{
					testRefreshTokenWoFID.Key(): testRefreshTokenWithFID,
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
			contract: &Contract{
				RefreshTokens: map[string]RefreshToken{
					testRefreshTokenWoFID.Key(): testRefreshTokenWithFID,
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
			contract: &Contract{
				RefreshTokens: map[string]RefreshToken{
					testRefreshTokenWoFID.Key(): testRefreshTokenWithFID,
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
			contract: &Contract{
				RefreshTokens: map[string]RefreshToken{
					testRefreshTokenWoFID.Key():       testRefreshTokenWoFID,
					testRefreshTokenWithFID.Key():     testRefreshTokenWithFID,
					testRefreshTokenWoFIDAltCID.Key(): testRefreshTokenWoFIDAltCID,
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
			contract: &Contract{
				RefreshTokens: map[string]RefreshToken{
					testRefreshTokenWoFID.Key():       testRefreshTokenWoFID,
					testRefreshTokenWithFID.Key():     testRefreshTokenWithFID,
					testRefreshTokenWoFIDAltCID.Key(): testRefreshTokenWoFIDAltCID,
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

		got, err := m.readRefreshToken(test.args.homeAccountID, test.args.envAliases, test.args.familyID, test.args.clientID)
		switch {
		case test.err && err == nil:
			t.Errorf("TestDefaultStorageManagerreadRefreshToken(%s): got err == nil, want err != nil", test.name)
			continue
		case !test.err && err != nil:
			t.Errorf("TestDefaultStorageManagerreadRefreshToken(%s): got err == %s, want err == nil", test.name, err)
			continue
		case err != nil:
			continue
		}
		if diff := pretty.Compare(test.want, got); diff != "" {
			t.Errorf("TestDefaultStorageManagerreadRefreshToken(%s): -want/+got:\n%s", test.name, diff)
		}
	}
}

func TestWriteRefreshToken(t *testing.T) {
	storageManager := New()
	testRefreshToken := NewRefreshToken(
		"hid",
		"env",
		"cid",
		"secret",
		"fid",
	)

	key := testRefreshToken.Key()

	err := storageManager.writeRefreshToken(testRefreshToken)
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
	contract := &Contract{
		AccessTokens: map[string]AccessToken{
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
		RefreshTokens: map[string]RefreshToken{
			"uid.utid-login.windows.net-refreshtoken-my_client_id--s2 s1 s3": {
				Target:         defaultScopes,
				Environment:    defaultEnvironment,
				CredentialType: rtCredType,
				Secret:         rtSecret,
				ClientID:       defaultClientID,
				HomeAccountID:  defaultHID,
			},
		},
		IDTokens: map[string]IDToken{
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
		AppMetaData: map[string]AppMetaData{
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
	if manager.Contract().AppMetaData["AppMetadata-login.windows.net-my_client_id"].FamilyID != "" {
		t.Errorf("TestStorageManagerDeserialize(app metadata family id): got %q, want empty string", manager.Contract().AppMetaData["AppMetadata-login.windows.net-my_client_id"].FamilyID)
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
		token AccessToken
		err   bool
	}{
		{
			desc:  "Success",
			token: NewAccessToken("hid", "env", "realm", "cid", cachedAt, expiresOn, extended, "openid", "secret"),
		},
		{
			desc:  "ExpiresOnUnixTimestamp has expired",
			token: NewAccessToken("hid", "env", "realm", "cid", cachedAt, badExpiresOn, extended, "openid", "secret"),
			err:   true,
		},
		{
			desc:  "Success",
			token: NewAccessToken("hid", "env", "realm", "cid", badCachedAt, expiresOn, extended, "openid", "secret"),
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

func TestRead(t *testing.T) {
	mockWebRequestManager := new(requests.MockWebRequestManager)

	accessTokenCacheItem := NewAccessToken(
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
	testIDToken := NewIDToken(
		"hid",
		"env",
		"realm",
		"cid",
		"secret",
	)
	testAppMeta := NewAppMetaData("fid", "cid", "env")
	testRefreshToken := NewRefreshToken(
		"hid",
		"env",
		"cid",
		"secret",
		"fid",
	)
	testAccount := msalbase.NewAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")

	contract := &Contract{
		RefreshTokens: map[string]RefreshToken{
			testRefreshToken.Key(): testRefreshToken,
		},
		Accounts: map[string]msalbase.Account{
			testAccount.Key(): testAccount,
		},
		AppMetaData: map[string]AppMetaData{
			testAppMeta.Key(): testAppMeta,
		},
		IDTokens: map[string]IDToken{
			testIDToken.Key(): testIDToken,
		},
		AccessTokens: map[string]AccessToken{
			accessTokenCacheItem.Key(): accessTokenCacheItem,
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
	got, err := manager.Read(context.Background(), authParameters, mockWebRequestManager)
	if err != nil {
		t.Fatalf("TestRead: got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestRead: -want/+got:\n%s", diff)
	}
}

func TestWrite(t *testing.T) {
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
	testRefreshToken := NewRefreshToken(
		"testUID.testUtid",
		"env",
		"cid",
		"refreshToken",
		"fid",
	)

	AccessToken := NewAccessToken(
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

	testIDToken := NewIDToken(
		"testUID.testUtid",
		"env",
		"realm",
		"cid",
		"idToken",
	)

	testAccount := msalbase.NewAccount("testUID.testUtid", "env", "realm", "lid", msalbase.MSSTS, "username")
	testAppMeta := NewAppMetaData("fid", "cid", "env")

	actualAccount, err := cacheManager.Write(authParams, tokenResponse)
	if err != nil {
		t.Errorf("Error should be nil; instead, it is %v", err)
	}
	if !reflect.DeepEqual(actualAccount, testAccount) {
		t.Errorf("Actual account %+v differs from expected account %+v", actualAccount, testAccount)
	}

	gotRefresh, ok := cacheManager.Contract().RefreshTokens[testRefreshToken.Key()]
	if !ok {
		t.Fatalf("TestWrite(refresh token): refresh token was not written as expected")
	}
	if diff := pretty.Compare(testRefreshToken, gotRefresh); diff != "" {
		t.Fatalf("TestWrite(refresh token): -want/+got\n%s", diff)
	}

	gotAccess, ok := cacheManager.Contract().AccessTokens[AccessToken.Key()]
	if !ok {
		t.Fatalf("TestWrite(access token): access token was not written as expected")
	}
	if diff := pretty.Compare(AccessToken, gotAccess); diff != "" {
		t.Fatalf("TestWrite(access token): -want/+got\n%s", diff)
	}

	gotToken, ok := cacheManager.Contract().IDTokens[testIDToken.Key()]
	if !ok {
		t.Fatalf("TestWrite(id token): id token was not written as expected")
	}
	if diff := pretty.Compare(testIDToken, gotToken); diff != "" {
		t.Fatalf("TestWrite(id token): -want/+got\n%s", diff)
	}

	gotAccount, ok := cacheManager.Contract().Accounts[testAccount.Key()]
	if !ok {
		t.Fatalf("TestWrite(account): account was not written as expected")
	}
	if diff := pretty.Compare(testAccount, gotAccount); diff != "" {
		t.Fatalf("TestWrite(account): -want/+got\n%s", diff)
	}

	gotMeta, ok := cacheManager.Contract().AppMetaData[testAppMeta.Key()]
	if !ok {
		t.Fatalf("TestWrite(app metadata): metadata was not written as expected")
	}
	if diff := pretty.Compare(testAppMeta, gotMeta); diff != "" {
		t.Fatalf("TestWrite(app metadata): -want/+got\n%s", diff)
	}
}
