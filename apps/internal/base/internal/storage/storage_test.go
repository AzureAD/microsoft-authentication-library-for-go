// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package storage

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
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
	rtSecret           = "a refresh token"
	idCred             = "IdToken"
	idSecret           = "header.eyJvaWQiOiAib2JqZWN0MTIzNCIsICJwcmVmZXJyZWRfdXNlcm5hbWUiOiAiSm9obiBEb2UiLCAic3ViIjogInN1YiJ9.signature"
	accUser            = "John Doe"
	accLID             = "object1234"
	accAuth            = "MSSTS"
)

var (
	atCached  = time.Unix(1000, 0)
	atExpires = time.Unix(4600, 0)
)

func newForTest(authorityClient aadInstanceDiscoveryer) *Manager {
	m := &Manager{requests: authorityClient, aadCache: make(map[string]authority.InstanceDiscoveryMetadata)}
	m.contract = NewContract()
	return m
}

type fakeDiscoveryResponser struct {
	err bool
	ret authority.InstanceDiscoveryResponse
}

func (f *fakeDiscoveryResponser) AADInstanceDiscovery(ctx context.Context, authorityInfo authority.Info) (authority.InstanceDiscoveryResponse, error) {
	if f.err {
		return authority.InstanceDiscoveryResponse{}, errors.New("error")
	}
	return f.ret, nil
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
		t.Fatalf("Scopes %v and %v are supposed to be the same", scopesOne, scopesTwo)
	}
	scopesUpperCase := "openid User.Write User.Read"
	if !isMatchingScopes(scopesOne, scopesUpperCase) {
		t.Fatalf("Scopes %v and %v are supposed to be the same as the comparison is case insensitive", scopesOne, scopesUpperCase)
	}
	errorScopes := "openid user.read hello"
	if isMatchingScopes(scopesOne, errorScopes) {
		t.Fatalf("Scopes %v and %v are not supposed to be the same", scopesOne, errorScopes)
	}
}

func TestAllAccounts(t *testing.T) {
	testAccOne := shared.NewAccount("hid", "env", "realm", "lid", accAuth, "username")
	testAccTwo := shared.NewAccount("HID", "ENV", "REALM", "LID", accAuth, "USERNAME")
	cache := &Contract{
		Accounts: map[string]shared.Account{
			testAccOne.Key(): testAccOne,
			testAccTwo.Key(): testAccTwo,
		},
	}

	storageManager := Manager{}
	storageManager.update(cache)

	actualAccounts := storageManager.AllAccounts()
	// AllAccounts() is unstable in that the order can be reversed between calls.
	// This fixes that.
	sort.Slice(
		actualAccounts,
		func(i, j int) bool {
			return actualAccounts[i].HomeAccountID > actualAccounts[j].HomeAccountID
		},
	)

	expectedAccounts := []shared.Account{testAccOne, testAccTwo}
	if diff := pretty.Compare(expectedAccounts, actualAccounts); diff != "" {
		t.Errorf("Actual accounts differ from expected accounts: -want/+got:\n%s", diff)
	}
}

func TestReadAccessToken(t *testing.T) {
	now := time.Now()
	testAccessToken := NewAccessToken(
		"hid",
		"env",
		"realm",
		"cid",
		now,
		now,
		now,
		"openid user.read",
		"secret",
	)
	cache := &Contract{
		AccessTokens: map[string]AccessToken{
			testAccessToken.Key(): testAccessToken,
		},
	}
	storageManager := newForTest(nil)
	storageManager.update(cache)

	retAccessToken := storageManager.readAccessToken(
		"hid",
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
		[]string{"user.read", "openid"},
	)
	if diff := pretty.Compare(testAccessToken, retAccessToken); diff != "" {
		t.Fatalf("Returned access token is not the same as expected access token: -want/+got:\n%s", diff)
	}
	retAccessToken = storageManager.readAccessToken(
		"this_should_break_it",
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
		[]string{"user.read", "openid"},
	)
	if !reflect.ValueOf(retAccessToken).IsZero() {
		t.Fatal("expected to find no access token")
	}
}

func TestWriteAccessToken(t *testing.T) {
	now := time.Now()
	storageManager := newForTest(nil)
	testAccessToken := NewAccessToken(
		"hid",
		"env",
		"realm",
		"cid",
		now,
		now,
		now,
		"openid",
		"secret",
	)

	key := testAccessToken.Key()
	err := storageManager.writeAccessToken(testAccessToken)
	if err != nil {
		t.Fatalf("TestwriteAccessToken: got err == %s, want err == nil", err)
	}

	if diff := pretty.Compare(testAccessToken, storageManager.contract.AccessTokens[key]); diff != "" {
		t.Errorf("TestwriteAccessToken: -want/+got:\n%s", diff)
	}
}

func TestReadAccount(t *testing.T) {
	testAcc := shared.NewAccount("hid", "env", "realm", "lid", accAuth, "username")

	cache := &Contract{
		Accounts: map[string]shared.Account{
			testAcc.Key(): testAcc,
		},
	}
	storageManager := newForTest(nil)
	storageManager.update(cache)

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
	storageManager := newForTest(nil)
	testAcc := shared.NewAccount("hid", "env", "realm", "lid", accAuth, "username")

	key := testAcc.Key()
	err := storageManager.writeAccount(testAcc)
	if err != nil {
		t.Fatalf("TestwriteAccount: got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAcc, storageManager.contract.Accounts[key]); diff != "" {
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
	storageManager := newForTest(nil)
	storageManager.update(cache)

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
	storageManager := newForTest(nil)

	testAppMeta := NewAppMetaData("fid", "cid", "env")
	key := testAppMeta.Key()
	err := storageManager.writeAppMetaData(testAppMeta)
	if err != nil {
		t.Fatalf("TestwriteAppMetaData: got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAppMeta, storageManager.contract.AppMetaData[key]); diff != "" {
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
	storageManager := newForTest(nil)
	storageManager.update(cache)

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
	storageManager := newForTest(nil)
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

	if diff := pretty.Compare(testIDToken, storageManager.contract.IDTokens[key]); diff != "" {
		t.Errorf("TestwriteIDToken: -want/+got:\n%s", diff)
	}
}

func TestDefaultStorageManagerreadRefreshToken(t *testing.T) {
	testRefreshTokenWithFID := accesstokens.NewRefreshToken(

		"hid",
		"env",
		"cid",
		"secret",
		"fid",
	)
	testRefreshTokenWoFID := accesstokens.NewRefreshToken(
		"hid",
		"env",
		"cid",
		"secret",
		"",
	)
	testRefreshTokenWoFIDAltCID := accesstokens.NewRefreshToken(
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
		want     accesstokens.RefreshToken
		err      bool
	}{
		{
			name: "Token without fid, read with fid, cid, env, and hid",
			contract: &Contract{
				RefreshTokens: map[string]accesstokens.RefreshToken{
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
				RefreshTokens: map[string]accesstokens.RefreshToken{
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
				RefreshTokens: map[string]accesstokens.RefreshToken{
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
				RefreshTokens: map[string]accesstokens.RefreshToken{
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
				RefreshTokens: map[string]accesstokens.RefreshToken{
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
				RefreshTokens: map[string]accesstokens.RefreshToken{
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
				RefreshTokens: map[string]accesstokens.RefreshToken{
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
				RefreshTokens: map[string]accesstokens.RefreshToken{
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
				RefreshTokens: map[string]accesstokens.RefreshToken{
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
				RefreshTokens: map[string]accesstokens.RefreshToken{
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
		m.update(test.contract)

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
	storageManager := newForTest(nil)
	testRefreshToken := accesstokens.NewRefreshToken(
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
	if !reflect.DeepEqual(storageManager.contract.RefreshTokens[key], testRefreshToken) {
		t.Errorf("Added refresh token %v differs from expected refresh token %v",
			storageManager.contract.RefreshTokens[key],
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
				Environment:       defaultEnvironment,
				CredentialType:    "AccessToken",
				Secret:            accessTokenSecret,
				Realm:             defaultRealm,
				Scopes:            defaultScopes,
				ClientID:          defaultClientID,
				CachedAt:          internalTime.Unix{T: atCached},
				HomeAccountID:     defaultHID,
				ExpiresOn:         internalTime.Unix{T: atExpires},
				ExtendedExpiresOn: internalTime.Unix{T: atExpires},
			},
		},
		RefreshTokens: map[string]accesstokens.RefreshToken{
			"uid.utid-login.windows.net-refreshtoken-my_client_id--s2 s1 s3": {
				Target:         defaultScopes,
				Environment:    defaultEnvironment,
				CredentialType: "RefreshToken",
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
		Accounts: map[string]shared.Account{
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

	manager := newForTest(nil)
	manager.update(contract)

	_, err := manager.Marshal()
	if err != nil {
		t.Errorf("Error should be nil; instead it is %v", err)
	}
}

func TestUnmarshal(t *testing.T) {
	manager := newForTest(nil)
	b, err := os.ReadFile(testFile)
	if err != nil {
		panic(err)
	}

	err = manager.Unmarshal(b)
	if err != nil {
		t.Fatalf("TestUnmarshal(unmarshal): got err == %s, want err == nil", err)
	}

	actualAccessTokenSecret := manager.contract.AccessTokens["uid.utid-login.windows.net-accesstoken-my_client_id-contoso-s2 s1 s3"].Secret
	if accessTokenSecret != actualAccessTokenSecret {
		t.Errorf("TestUnmarshal(access token secret):got %q, want %q", actualAccessTokenSecret, accessTokenSecret)
	}

	actualRTSecret := manager.contract.RefreshTokens["uid.utid-login.windows.net-refreshtoken-my_client_id--s2 s1 s3"].Secret
	if diff := pretty.Compare(rtSecret, actualRTSecret); diff != "" {
		t.Errorf("TestUnmarshal(refresh token secret): -want/+got:\n%s", diff)
	}

	actualIDSecret := manager.contract.IDTokens["uid.utid-login.windows.net-idtoken-my_client_id-contoso-"].Secret
	if diff := pretty.Compare(idSecret, actualIDSecret); diff != "" {
		t.Errorf("TestUnmarshal(id secret): -want/+got:\n%s", diff)
	}
	actualUser := manager.contract.Accounts["uid.utid-login.windows.net-contoso"].PreferredUsername
	if diff := pretty.Compare(actualUser, accUser); diff != "" {
		t.Errorf("TestUnmarshal(actula user): -want/+got:\n%s", diff)
	}
	if manager.contract.AppMetaData["AppMetadata-login.windows.net-my_client_id"].FamilyID != "" {
		t.Errorf("TestUnmarshal(app metadata family id): got %q, want empty string", manager.contract.AppMetaData["AppMetadata-login.windows.net-my_client_id"].FamilyID)
	}
}

func TestIsAccessTokenValid(t *testing.T) {
	cachedAt := time.Now()
	badCachedAt := time.Now().Add(500 * time.Second)
	expiresOn := time.Now().Add(1000 * time.Second)
	badExpiresOn := time.Now().Add(200 * time.Second)
	extended := time.Now()

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
	accessTokenCacheItem := NewAccessToken(
		"hid",
		"env",
		"realm",
		"cid",
		time.Now(),
		time.Now().Add(1000*time.Second),
		time.Now(),
		"openid profile",
		"secret",
	)
	testIDToken := NewIDToken("hid", "env", "realm", "cid", "secret")
	testAppMeta := NewAppMetaData("fid", "cid", "env")
	testRefreshToken := accesstokens.NewRefreshToken("hid", "env", "cid", "secret", "fid")
	testAccount := shared.NewAccount("hid", "env", "realm", "lid", accAuth, "username")

	contract := &Contract{
		RefreshTokens: map[string]accesstokens.RefreshToken{
			testRefreshToken.Key(): testRefreshToken,
		},
		Accounts: map[string]shared.Account{
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

	authInfo := authority.Info{
		Host:   "env",
		Tenant: "realm",
	}
	authParameters := authority.AuthParams{
		HomeAccountID: "hid",
		AuthorityInfo: authInfo,
		ClientID:      "cid",
		Scopes:        []string{"openid", "profile"},
	}

	tests := []struct {
		desc        string
		discRespErr bool
		discResp    authority.InstanceDiscoveryResponse
		err         bool
		want        TokenResponse
	}{
		{
			desc:        "Error: AAD Discovery Fails",
			discRespErr: true,
			err:         true,
		},
		{
			desc: "Success",
			discResp: authority.InstanceDiscoveryResponse{
				TenantDiscoveryEndpoint: "tenant",
				Metadata: []authority.InstanceDiscoveryMetadata{
					{
						Aliases: []string{"env", "alias2"},
					},
					{
						Aliases: []string{"alias3", "alias4"},
					},
				},
			},
			want: TokenResponse{
				AccessToken:  accessTokenCacheItem,
				RefreshToken: testRefreshToken,
				IDToken:      testIDToken,
				Account:      testAccount,
			},
		},
	}

	for _, test := range tests {
		responder := &fakeDiscoveryResponser{err: test.discRespErr, ret: test.discResp}
		manager := newForTest(responder)
		manager.update(contract)

		got, err := manager.Read(context.Background(), authParameters)
		switch {
		case err == nil && test.err:
			t.Errorf("TestRead(%s): got err == nil, want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestRead(%s): got err == %s, want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if diff := pretty.Compare(test.want, got); diff != "" {
			t.Errorf("TestRead(%s): -want/+got:\n%s", test.desc, diff)
		}
	}
}

func removeSubSeconds(t time.Time) time.Time {
	t = t.Add(-time.Duration(t.Nanosecond()))
	return t
}

func TestWrite(t *testing.T) {
	now := removeSubSeconds(time.Now().UTC())

	cacheManager := newForTest(nil)
	clientInfo := accesstokens.ClientInfo{
		UID:  "testUID",
		UTID: "testUtid",
	}
	idToken := accesstokens.IDToken{
		RawToken:          "idToken",
		Oid:               "lid",
		PreferredUsername: "username",
	}
	expiresOn := internalTime.DurationTime{T: now.Add(1000 * time.Second)}
	tokenResponse := accesstokens.TokenResponse{
		AccessToken:   "accessToken",
		RefreshToken:  "refreshToken",
		IDToken:       idToken,
		FamilyID:      "fid",
		ClientInfo:    clientInfo,
		GrantedScopes: accesstokens.Scopes{Slice: []string{"openid", "profile"}},
		ExpiresOn:     expiresOn,
		ExtExpiresOn:  internalTime.DurationTime{T: now},
	}
	authInfo := authority.Info{Host: "env", Tenant: "realm", AuthorityType: accAuth}
	authParams := authority.AuthParams{
		AuthorityInfo: authInfo,
		ClientID:      "cid",
	}
	testRefreshToken := accesstokens.NewRefreshToken(
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
		now,
		now.Add(1000*time.Second),
		now,
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

	testAccount := shared.NewAccount("testUID.testUtid", "env", "realm", "lid", accAuth, "username")
	testAppMeta := NewAppMetaData("fid", "cid", "env")

	actualAccount, err := cacheManager.Write(authParams, tokenResponse)
	if err != nil {
		t.Errorf("Error should be nil; instead, it is %v", err)
	}
	if !reflect.DeepEqual(actualAccount, testAccount) {
		t.Errorf("Actual account %+v differs from expected account %+v", actualAccount, testAccount)
	}

	gotRefresh, ok := cacheManager.contract.RefreshTokens[testRefreshToken.Key()]
	if !ok {
		t.Fatalf("TestWrite(refresh token): refresh token was not written as expected")
	}
	if diff := pretty.Compare(testRefreshToken, gotRefresh); diff != "" {
		t.Fatalf("TestWrite(refresh token): -want/+got\n%s", diff)
	}

	gotAccess, ok := cacheManager.contract.AccessTokens[AccessToken.Key()]
	if !ok {
		t.Fatalf("TestWrite(access token): access token was not written as expected")
	}

	// CachedAt is generated for this exact moment, not from input.  We would need to
	// fake time.Now() call with a var now = time.Now() in the package in order to
	// control this or we can just ignore this value.  We are going to simply check its
	// not zero and then zero it for our got/want comparison.
	if gotAccess.CachedAt.T.IsZero() {
		t.Fatalf("TestWrite(access token): AccessToken.CachedAt is the zero value, which is incorrect")
	}
	gotAccess.CachedAt = internalTime.Unix{}
	AccessToken.CachedAt = internalTime.Unix{}
	if diff := pretty.Compare(AccessToken, gotAccess); diff != "" {
		t.Fatalf("TestWrite(access token): -want/+got\n%s", diff)
	}

	gotToken, ok := cacheManager.contract.IDTokens[testIDToken.Key()]
	if !ok {
		t.Fatalf("TestWrite(id token): id token was not written as expected")
	}
	if diff := pretty.Compare(testIDToken, gotToken); diff != "" {
		t.Fatalf("TestWrite(id token): -want/+got\n%s", diff)
	}

	gotAccount, ok := cacheManager.contract.Accounts[testAccount.Key()]
	if !ok {
		t.Fatalf("TestWrite(account): account was not written as expected")
	}
	if diff := pretty.Compare(testAccount, gotAccount); diff != "" {
		t.Fatalf("TestWrite(account): -want/+got\n%s", diff)
	}

	gotMeta, ok := cacheManager.contract.AppMetaData[testAppMeta.Key()]
	if !ok {
		t.Fatalf("TestWrite(app metadata): metadata was not written as expected")
	}
	if diff := pretty.Compare(testAppMeta, gotMeta); diff != "" {
		t.Fatalf("TestWrite(app metadata): -want/+got\n%s", diff)
	}
}
func TestRemoveRefreshTokens(t *testing.T) {
	storageManager := newForTest(nil)
	testRefreshToken := accesstokens.NewRefreshToken("hid", "env", "cid", "secret", "fid")
	key := testRefreshToken.Key()
	contract := &Contract{
		RefreshTokens: map[string]accesstokens.RefreshToken{
			key: testRefreshToken,
		},
	}
	storageManager.update(contract)
	storageManager.removeRefreshTokens("hid", "env", "cid")

	if val, ok := storageManager.contract.RefreshTokens[key]; ok {
		t.Fatalf("TestRemoveRefreshTokens: got refreshToken == %s, want refreshToken == empty", val)
	}
}

func TestRemoveAccessTokens(t *testing.T) {
	now := time.Now()
	storageManager := newForTest(nil)
	testAccessToken := NewAccessToken("hid", "env", "realm", "cid", now, now, now, "openid", "secret")
	key := testAccessToken.Key()
	contract := &Contract{
		AccessTokens: map[string]AccessToken{
			key: testAccessToken,
		},
	}
	storageManager.update(contract)
	storageManager.removeAccessTokens("hid", "env")

	if val, ok := storageManager.contract.AccessTokens[key]; ok {
		t.Fatalf("TestRemoveAccessTokens: got accessToken == %s, want accessToken == empty", val)
	}
}

func TestRemoveIDTokens(t *testing.T) {
	storageManager := newForTest(nil)
	testIDToken := NewIDToken("hid", "env", "realm", "cid", "secret")
	key := testIDToken.Key()
	contract := &Contract{
		IDTokens: map[string]IDToken{
			key: testIDToken,
		},
	}
	storageManager.update(contract)
	storageManager.removeIDTokens("hid", "env")

	if val, ok := storageManager.contract.IDTokens[key]; ok {
		t.Fatalf("TestRemoveIDTokens: got IDToken == %s, want IDToken == empty", val)
	}
}

func TestRemoveAccountObject(t *testing.T) {
	storageManager := newForTest(nil)
	testAccount := shared.NewAccount("hid", "env", "realm", "lid", accAuth, "username")
	key := testAccount.Key()
	contract := &Contract{
		Accounts: map[string]shared.Account{
			key: testAccount,
		},
	}
	storageManager.update(contract)
	storageManager.removeAccounts("hid", "env")

	if val, ok := storageManager.contract.Accounts[key]; ok {
		t.Fatalf("TestRemoveAccountObject: got Account == %s, want Account == empty", val)
	}
}

func TestRemoveAccount(t *testing.T) {
	now := time.Now()
	testAccessToken := NewAccessToken("hid", "env", "realm", "cid", now, now, now, "openid profile", "secret")
	testIDToken := NewIDToken("hid", "env", "realm", "cid", "secret")
	testAppMeta := NewAppMetaData("fid", "cid", "env")
	testRefreshToken := accesstokens.NewRefreshToken("hid", "env", "cid", "secret", "fid")
	testAccount := shared.NewAccount("hid", "env", "realm", "lid", accAuth, "username")

	contract := &Contract{
		RefreshTokens: map[string]accesstokens.RefreshToken{
			testRefreshToken.Key(): testRefreshToken,
		},
		Accounts: map[string]shared.Account{
			testAccount.Key(): testAccount,
		},
		AppMetaData: map[string]AppMetaData{
			testAppMeta.Key(): testAppMeta,
		},
		IDTokens: map[string]IDToken{
			testIDToken.Key(): testIDToken,
		},
		AccessTokens: map[string]AccessToken{
			testAccessToken.Key(): testAccessToken,
		},
	}
	manager := newForTest(nil)
	manager.update(contract)
	manager.RemoveAccount(testAccount, "cid")
	if val, ok := manager.contract.RefreshTokens[testRefreshToken.Key()]; ok {
		t.Fatalf("TestRemoveAccount: got refreshToken == %s, want refreshToken == empty", val)
	}
	if val, ok := manager.contract.AccessTokens[testAccessToken.Key()]; ok {
		t.Fatalf("TestRemoveAccount: got accessToken == %s, want accessToken == empty", val)
	}
	if val, ok := manager.contract.IDTokens[testIDToken.Key()]; ok {
		t.Fatalf("TestRemoveAccount: got IDToken == %s, want IDToken == empty", val)
	}
	if val, ok := manager.contract.Accounts[testAccount.Key()]; ok {
		t.Fatalf("TestRemoveAccount: got Account == %s, want Account == empty", val)
	}
}

func TestRemoveEmptyAccount(t *testing.T) {
	now := time.Now()
	testAccessToken := NewAccessToken("hid", "env", "realm", "cid", now, now, now, "openid profile", "secret")
	testIDToken := NewIDToken("hid", "env", "realm", "cid", "secret")
	testAppMeta := NewAppMetaData("fid", "cid", "env")
	testRefreshToken := accesstokens.NewRefreshToken("hid", "env", "cid", "secret", "fid")
	testAccount := shared.NewAccount("hid", "env", "realm", "lid", accAuth, "username")

	contract := &Contract{
		RefreshTokens: map[string]accesstokens.RefreshToken{
			testRefreshToken.Key(): testRefreshToken,
		},
		Accounts: map[string]shared.Account{
			testAccount.Key(): testAccount,
		},
		AppMetaData: map[string]AppMetaData{
			testAppMeta.Key(): testAppMeta,
		},
		IDTokens: map[string]IDToken{
			testIDToken.Key(): testIDToken,
		},
		AccessTokens: map[string]AccessToken{
			testAccessToken.Key(): testAccessToken,
		},
	}
	manager := newForTest(nil)
	manager.update(contract)
	manager.RemoveAccount(shared.Account{}, "cid")
	if _, ok := manager.contract.RefreshTokens[testRefreshToken.Key()]; !ok {
		t.Fatalf("TestRemoveEmptyAccount: got refreshToken == empty, want refreshToken == %s", testRefreshToken)
	}
	if _, ok := manager.contract.AccessTokens[testAccessToken.Key()]; !ok {
		t.Fatalf("TestRemoveEmptyAccount: got accessToken == empty, want accessToken == %s", testAccessToken)
	}
	if _, ok := manager.contract.IDTokens[testIDToken.Key()]; !ok {
		t.Fatalf("TestRemoveEmptyAccount: got IDToken == empty, want IDToken == %s", testIDToken)
	}
	if _, ok := manager.contract.Accounts[testAccount.Key()]; !ok {
		t.Fatalf("TestRemoveEmptyAccount: got Account == empty, want Account == %s", testAccount)
	}
}
