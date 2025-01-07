// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package storage

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
	"github.com/kylelemons/godebug/pretty"
)

func newPartitionedManagerForTest(authorityClient aadInstanceDiscoveryer) *PartitionedManager {
	m := &PartitionedManager{requests: authorityClient, aadCache: make(map[string]authority.InstanceDiscoveryMetadata)}
	m.contract = NewInMemoryContract()
	return m
}

func TestOBOAccessTokenScopes(t *testing.T) {
	fakeAuthority := "fakeauthority"
	mgr := newPartitionedManagerForTest(&fakeDiscoveryResponser{
		ret: authority.InstanceDiscoveryResponse{
			Metadata: []authority.InstanceDiscoveryMetadata{
				{Aliases: []string{fakeAuthority}},
			},
		},
	})
	upn := "upn"
	idt := accesstokens.IDToken{
		Oid:               upn + "-oid",
		PreferredUsername: upn,
		TenantID:          "tenant",
		UPN:               upn,
	}
	authParams := []authority.AuthParams{}
	for _, scope := range [][]string{{"scopeA"}, {"scopeB"}} {
		ap := authority.AuthParams{
			AuthorityInfo: authority.Info{
				AuthorityType: authority.AAD,
				Host:          fakeAuthority,
				Tenant:        idt.TenantID,
			},
			AuthorizationType: authority.ATOnBehalfOf,
			ClientID:          "client-id",
			Scopes:            scope,
			UserAssertion:     upn + "-assertion",
			Username:          idt.PreferredUsername,
			AuthnScheme:       &authority.BearerAuthenticationScheme{},
		}
		_, err := mgr.Write(
			ap,
			accesstokens.TokenResponse{
				AccessToken:   scope[0] + "-at",
				ClientInfo:    accesstokens.ClientInfo{UID: upn, UTID: idt.TenantID},
				ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(time.Hour)},
				GrantedScopes: accesstokens.Scopes{Slice: scope},
				IDToken:       idt,
				RefreshToken:  upn + "-rt",
				TokenType:     "Bearer",
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		authParams = append(authParams, ap)
	}

	for _, ap := range authParams {
		tr, err := mgr.Read(context.Background(), ap)
		if err != nil {
			t.Fatal(err)
		}
		if tr.AccessToken.Secret != ap.Scopes[0]+"-at" {
			t.Fatalf(`unexpected access token "%s"`, tr.AccessToken.Secret)
		}
	}
}

func TestOBOPartitioning(t *testing.T) {
	fakeAuthority := "fakeauthority"
	mgr := newPartitionedManagerForTest(&fakeDiscoveryResponser{
		ret: authority.InstanceDiscoveryResponse{
			Metadata: []authority.InstanceDiscoveryMetadata{
				{Aliases: []string{fakeAuthority}},
			},
		},
	})
	scopes := []string{"scope"}
	accounts := make([]shared.Account, 2)
	authParams := make([]authority.AuthParams, len(accounts))
	for i := 0; i < len(accounts); i++ {
		upn := fmt.Sprintf("%d", i)
		idt := accesstokens.IDToken{
			Oid:               upn + "-oid",
			PreferredUsername: upn,
			TenantID:          "tenant",
			UPN:               upn,
		}
		authParams[i] = authority.AuthParams{
			AuthorityInfo: authority.Info{
				AuthorityType: authority.AAD,
				Host:          fakeAuthority,
				Tenant:        idt.TenantID,
			},
			AuthorizationType: authority.ATOnBehalfOf,
			ClientID:          "client-id",
			Scopes:            scopes,
			UserAssertion:     upn + "-assertion",
			Username:          idt.PreferredUsername,
			AuthnScheme:       &authority.BearerAuthenticationScheme{},
		}
		account, err := mgr.Write(
			authParams[i],
			accesstokens.TokenResponse{
				AccessToken:   upn + "-at",
				ClientInfo:    accesstokens.ClientInfo{UID: upn, UTID: idt.TenantID},
				ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(time.Hour)},
				GrantedScopes: accesstokens.Scopes{Slice: scopes},
				IDToken:       idt,
				RefreshToken:  upn + "-rt",
				TokenType:     "Bearer",
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		accounts[i] = account
	}

	for i, ap := range authParams {
		tr, err := mgr.Read(context.Background(), ap)
		if err != nil {
			t.Fatal(err)
		}
		if tr.AccessToken.Secret != accounts[i].PreferredUsername+"-at" {
			t.Fatalf(`unexpected access token "%s"`, tr.AccessToken.Secret)
		}
	}
}

func TestReadPartitionedAccessToken(t *testing.T) {
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
		"Bearer",
		"",
	)
	testAccessToken.UserAssertionHash = "user_assertion_hash"
	cache := &InMemoryContract{
		AccessTokensPartition: map[string]map[string]AccessToken{
			"at_partition": {testAccessToken.Key(): testAccessToken},
		},
	}
	storageManager := newPartitionedManagerForTest(nil)
	storageManager.update(cache)

	retAccessToken, err := storageManager.readAccessToken(
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
		"user_assertion_hash",
		[]string{"user.read", "openid"},
		"at_partition",
		"Bearer",
		"",
	)
	if err != nil {
		t.Errorf("TestReadPartitionedAccessToken: got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAccessToken, retAccessToken); diff != "" {
		t.Fatalf("Returned access token is not the same as expected access token: -want/+got:\n%s", diff)
	}
	_, err = storageManager.readAccessToken(
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
		"this_should_break_it",
		[]string{"user.read", "openid"},
		"at_partition",
		"Bearer",
		"",
	)
	if err == nil {
		t.Errorf("TestReadPartitionedAccessToken: got err == nil, want err != nil")
	}
}

func TestWritePartitionedAccessToken(t *testing.T) {
	now := time.Now()
	storageManager := newPartitionedManagerForTest(nil)
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
		"tokenType",
		"",
	)

	key := testAccessToken.Key()
	err := storageManager.writeAccessToken(testAccessToken, "at_partition")
	if err != nil {
		t.Fatalf("TestWritePartitionedAccessToken: got err == %s, want err == nil", err)
	}

	if diff := pretty.Compare(testAccessToken, storageManager.contract.AccessTokensPartition["at_partition"][key]); diff != "" {
		t.Errorf("TestWritePartitionedAccessToken: -want/+got:\n%s", diff)
	}
}

func TestReadPartitionedAccount(t *testing.T) {
	testAcc := shared.NewAccount("hid", "env", "realm", "lid", accAuth, "username")
	testAcc.UserAssertionHash = "user_assertion_hash"
	cache := &InMemoryContract{
		AccountsPartition: map[string]map[string]shared.Account{
			"acc_partition": {testAcc.Key(): testAcc},
		},
	}
	storageManager := newPartitionedManagerForTest(nil)
	storageManager.update(cache)

	returnedAccount, err := storageManager.readAccount([]string{"hello", "env", "test"}, "realm", "user_assertion_hash", "acc_partition")
	if err != nil {
		t.Fatalf("TestReadPartitionedAccount: got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAcc, returnedAccount); diff != "" {
		t.Errorf("TestReadPartitionedAccount: -want/+got:\n%s", diff)
	}

	_, err = storageManager.readAccount([]string{"hello", "env", "test"}, "realm", "this_should_break_it", "acc_partition")
	if err == nil {
		t.Errorf("TestReadPartitionedAccount: got err == nil, want err != nil")
	}
}

func TestWritePartitionedAccount(t *testing.T) {
	storageManager := newPartitionedManagerForTest(nil)
	testAcc := shared.NewAccount("hid", "env", "realm", "lid", accAuth, "username")
	testAcc.UserAssertionHash = "user_assertion_hash"

	key := testAcc.Key()
	err := storageManager.writeAccount(testAcc, "acc_partition")
	if err != nil {
		t.Fatalf("TestWritePartitionedAccount: got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAcc, storageManager.contract.AccountsPartition["acc_partition"][key]); diff != "" {
		t.Errorf("TestWritePartitionedAccount: -want/+got:\n%s", diff)
	}
}

func TestReadAppMetaDataPartitionedManager(t *testing.T) {
	testAppMeta := NewAppMetaData("fid", "cid", "env")

	cache := &InMemoryContract{
		AppMetaData: map[string]AppMetaData{
			testAppMeta.Key(): testAppMeta,
		},
	}
	storageManager := newPartitionedManagerForTest(nil)
	storageManager.update(cache)

	returnedAppMeta, err := storageManager.readAppMetaData([]string{"hello", "test", "env"}, "cid")
	if err != nil {
		t.Fatalf("TestreadAppMetaDataPartitionedManager(readAppMetaData): got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAppMeta, returnedAppMeta); diff != "" {
		t.Fatalf("TestreadAppMetaDataPartitionedManager(readAppMetaData): -want/+got:\n%s", diff)
	}

	_, err = storageManager.readAppMetaData([]string{"hello", "test", "env"}, "break_this")
	if err == nil {
		t.Fatalf("TestreadAppMetaDataPartitionedManager(bad readAppMetaData): got err == nil, want err != nil")
	}
}

func TestWriteAppMetaDataPartitionedManager(t *testing.T) {
	storageManager := newPartitionedManagerForTest(nil)

	testAppMeta := NewAppMetaData("fid", "cid", "env")
	key := testAppMeta.Key()
	err := storageManager.writeAppMetaData(testAppMeta)
	if err != nil {
		t.Fatalf("TestwriteAppMetaDataPartitionedManager: got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(testAppMeta, storageManager.contract.AppMetaData[key]); diff != "" {
		t.Errorf("TestwriteAppMetaDataPartitionedManager: -want/+got:\n%s", diff)
	}
}

func TestReadPartitionedIDToken(t *testing.T) {
	testIDToken := NewIDToken(
		"hid",
		"env",
		"realm",
		"cid",
		"secret",
	)
	testIDToken.UserAssertionHash = "user_assertion_hash"

	cache := &InMemoryContract{
		IDTokensPartition: map[string]map[string]IDToken{
			"idt_partition": {testIDToken.Key(): testIDToken},
		},
	}

	storageManager := newPartitionedManagerForTest(nil)
	storageManager.update(cache)

	returnedIDToken, err := storageManager.readIDToken(
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
		"user_assertion_hash",
		"idt_partition",
	)
	if err != nil {
		panic(err)
	}

	if diff := pretty.Compare(testIDToken, returnedIDToken); diff != "" {
		t.Fatalf("TestReadPartitionedIDToken(good token): -want/+got:\n%s", diff)
	}

	_, err = storageManager.readIDToken(
		[]string{"hello", "env", "test"},
		"realm",
		"cid",
		"this_should_break_it",
		"idt_partition",
	)
	if err == nil {
		t.Errorf("TestReadPartitionedIDToken(bad token): got err == nil, want err != nil")
	}
}

func TestWritePartitionedIDToken(t *testing.T) {
	storageManager := newPartitionedManagerForTest(nil)
	testIDToken := NewIDToken(
		"hid",
		"env",
		"realm",
		"cid",
		"secret",
	)
	testIDToken.UserAssertionHash = "user_assertion_hash"

	key := testIDToken.Key()

	err := storageManager.writeIDToken(testIDToken, "idt_partition")
	if err != nil {
		t.Fatalf("TestWritePartitionedIDToken: got err == %s, want err == nil", err)
	}

	if diff := pretty.Compare(testIDToken, storageManager.contract.IDTokensPartition["idt_partition"][key]); diff != "" {
		t.Errorf("TestWritePartitionedIDToken: -want/+got:\n%s", diff)
	}
}

func TestReadPartionedRefreshToken(t *testing.T) {
	testRefreshTokenWithFID := accesstokens.NewRefreshToken(
		"hid",
		"env",
		"cid",
		"secret",
		"fid",
	)
	testRefreshTokenWithFID.UserAssertionHash = "user_assertion_hash"
	testRefreshTokenWoFID := accesstokens.NewRefreshToken(
		"hid",
		"env",
		"cid",
		"secret",
		"",
	)
	testRefreshTokenWoFID.UserAssertionHash = "user_assertion_hash"
	testRefreshTokenWoFIDAltCID := accesstokens.NewRefreshToken(
		"hid",
		"env",
		"cid2",
		"secret",
		"",
	)
	testRefreshTokenWoFIDAltCID.UserAssertionHash = "user_assertion_hash"
	type args struct {
		envAliases        []string
		familyID          string
		clientID          string
		userAssertionHash string
	}

	tests := []struct {
		name     string
		contract *InMemoryContract
		args     args
		want     accesstokens.RefreshToken
		err      bool
	}{
		{
			name: "Token without fid, read with fid, cid, env, and hid",
			contract: &InMemoryContract{
				RefreshTokensPartition: map[string]map[string]accesstokens.RefreshToken{
					"rt_partition": {testRefreshTokenWoFID.Key(): testRefreshTokenWoFID},
				},
			},
			args: args{
				envAliases:        []string{"test", "env", "hello"},
				familyID:          "fid",
				clientID:          "cid",
				userAssertionHash: "user_assertion_hash",
			},
			want: testRefreshTokenWoFID,
		},
		{
			name: "Token without fid, read with cid, env, and hid",
			contract: &InMemoryContract{
				RefreshTokensPartition: map[string]map[string]accesstokens.RefreshToken{
					"rt_partition": {testRefreshTokenWoFID.Key(): testRefreshTokenWoFID},
				},
			},
			args: args{
				envAliases:        []string{"test", "env", "hello"},
				familyID:          "",
				clientID:          "cid",
				userAssertionHash: "user_assertion_hash",
			},
			want: testRefreshTokenWoFID,
		},
		{
			name: "Token without fid, verify CID is required",
			contract: &InMemoryContract{
				RefreshTokensPartition: map[string]map[string]accesstokens.RefreshToken{
					"rt_partition": {testRefreshTokenWoFID.Key(): testRefreshTokenWoFID},
				},
			},
			args: args{
				envAliases:        []string{"test", "env", "hello"},
				familyID:          "",
				clientID:          "",
				userAssertionHash: "user_assertion_hash",
			},
			err: true,
		},
		{
			name: "Token without fid, Verify env is required",
			contract: &InMemoryContract{
				RefreshTokensPartition: map[string]map[string]accesstokens.RefreshToken{
					"rt_partition": {testRefreshTokenWoFID.Key(): testRefreshTokenWoFID},
				},
			},
			args: args{
				envAliases:        []string{},
				familyID:          "",
				clientID:          "",
				userAssertionHash: "user_assertion_hash",
			},
			err: true,
		},
		{
			name: "Token with fid, read with fid, cid, env, and hid",
			contract: &InMemoryContract{
				RefreshTokensPartition: map[string]map[string]accesstokens.RefreshToken{
					"rt_partition": {testRefreshTokenWoFID.Key(): testRefreshTokenWithFID},
				},
			},
			args: args{
				envAliases:        []string{"test", "env", "hello"},
				familyID:          "fid",
				clientID:          "cid",
				userAssertionHash: "user_assertion_hash",
			},
			want: testRefreshTokenWithFID,
		},
		{
			name: "Token with fid, read with cid, env, and hid",
			contract: &InMemoryContract{
				RefreshTokensPartition: map[string]map[string]accesstokens.RefreshToken{
					"rt_partition": {testRefreshTokenWoFID.Key(): testRefreshTokenWithFID},
				},
			},
			args: args{
				envAliases:        []string{"test", "env", "hello"},
				familyID:          "",
				clientID:          "cid",
				userAssertionHash: "user_assertion_hash",
			},
			want: testRefreshTokenWithFID,
		},
		{
			name: "Token with fid, verify CID is not required", // match on hid, env, and has fid
			contract: &InMemoryContract{
				RefreshTokensPartition: map[string]map[string]accesstokens.RefreshToken{
					"rt_partition": {testRefreshTokenWoFID.Key(): testRefreshTokenWithFID},
				},
			},
			args: args{
				envAliases:        []string{"test", "env", "hello"},
				familyID:          "",
				clientID:          "",
				userAssertionHash: "user_assertion_hash",
			},
			want: testRefreshTokenWithFID,
		},
		{
			name: "Token with fid, Verify env is required",
			contract: &InMemoryContract{
				RefreshTokensPartition: map[string]map[string]accesstokens.RefreshToken{
					"rt_partition": {testRefreshTokenWoFID.Key(): testRefreshTokenWithFID},
				},
			},

			args: args{
				envAliases:        []string{},
				familyID:          "",
				clientID:          "",
				userAssertionHash: "user_assertion_hash",
			},
			err: true,
		},
		{
			name: "Multiple items in cache, given a fid, item with fid will be returned",
			contract: &InMemoryContract{
				RefreshTokensPartition: map[string]map[string]accesstokens.RefreshToken{
					"rt_partition": {
						testRefreshTokenWoFID.Key():       testRefreshTokenWoFID,
						testRefreshTokenWoFID.Key():       testRefreshTokenWithFID,
						testRefreshTokenWoFIDAltCID.Key(): testRefreshTokenWoFIDAltCID,
					},
				},
			},
			args: args{
				envAliases:        []string{},
				familyID:          "fid",
				clientID:          "cid",
				userAssertionHash: "user_assertion_hash",
			},
			err: true,
		},
		// Cannot guarentee that without an alternate cid which token will be
		// returned deterministically when HID, CID, and env match.
		{
			name: "Multiple items in cache, without a fid and with alternate CID, token with alternate CID is returned",
			contract: &InMemoryContract{
				RefreshTokensPartition: map[string]map[string]accesstokens.RefreshToken{
					"rt_partition": {
						testRefreshTokenWoFID.Key():       testRefreshTokenWoFID,
						testRefreshTokenWoFID.Key():       testRefreshTokenWithFID,
						testRefreshTokenWoFIDAltCID.Key(): testRefreshTokenWoFIDAltCID,
					},
				},
			},
			args: args{
				envAliases:        []string{},
				familyID:          "",
				clientID:          "cid2",
				userAssertionHash: "user_assertion_hash",
			},
			err: true,
		},
	}

	m := &PartitionedManager{}
	for _, test := range tests {
		m.update(test.contract)

		got, err := m.readRefreshToken(test.args.envAliases, test.args.familyID, test.args.clientID, test.args.userAssertionHash, "rt_partition")
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

func TestWritePartitionedRefreshToken(t *testing.T) {
	storageManager := newPartitionedManagerForTest(nil)
	testRefreshToken := accesstokens.NewRefreshToken(
		"hid",
		"env",
		"cid",
		"secret",
		"fid",
	)
	testRefreshToken.UserAssertionHash = "user_assertion_hash"

	key := testRefreshToken.Key()

	err := storageManager.writeRefreshToken(testRefreshToken, "rt_partition")
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(storageManager.contract.RefreshTokensPartition["rt_partition"][key], testRefreshToken) {
		t.Errorf("Added refresh token %v differs from expected refresh token %v",
			storageManager.contract.RefreshTokensPartition["rt_partition"][key],
			testRefreshToken)
	}
}
