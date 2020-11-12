// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"reflect"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
)

// TODO(jdoak): move test so it is close to new implementation.
// Make table driven.
func TestIsAccessTokenValid(t *testing.T) {
	cachedAt := time.Now().Unix()
	badCachedAt := time.Now().Unix() + 500
	expiresOn := time.Now().Unix() + 1000
	badExpiresOn := time.Now().Unix() + 200
	extended := time.Now().Unix()

	tests := []struct {
		desc  string
		token accessTokenCacheItem
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

func TestGetAllAccounts(t *testing.T) {
	accHidOne := "hid"
	accEnvOne := "env"
	accRealmOne := "realm"
	account1 := msalbase.Account{
		HomeAccountID: accHidOne,
		Environment:   accEnvOne,
		Realm:         accRealmOne,
	}
	accHidTwo := "testHID"
	accEnvTwo := "testEnv"
	accRealmTwo := "testRealm"
	account2 := msalbase.Account{
		HomeAccountID: accHidTwo,
		Environment:   accEnvTwo,
		Realm:         accRealmTwo,
	}
	expectedAccounts := []msalbase.Account{account1, account2}
	mockStorageManager := new(MockStorageManager)
	cacheManager := defaultCacheManager{storageManager: mockStorageManager}
	mockStorageManager.On("ReadAllAccounts").Return(expectedAccounts, nil)
	actualAccounts, err := cacheManager.GetAllAccounts()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(expectedAccounts, actualAccounts) {
		t.Errorf("Expected accounts %v differ from actual accounts %v", expectedAccounts, actualAccounts)
	}
}

func TestTryReadCache(t *testing.T) {
	mockStorageManager := new(MockStorageManager)
	mockWebRequestManager := new(requests.MockWebRequestManager)
	cacheManager := defaultCacheManager{storageManager: mockStorageManager}
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
	accessTokenCacheItem := createAccessTokenCacheItem(
		"hid",
		"env",
		"realm",
		"cid",
		time.Now().Unix(),
		time.Now().Unix()+1000,
		time.Now().Unix(),
		"openid",
		"secret",
	)
	mockStorageManager.On("ReadAccessToken",
		"hid",
		[]string{"env", "alias2"},
		"realm",
		"cid",
		[]string{"openid", "profile"}).Return(accessTokenCacheItem, nil)
	testIDToken := createIDTokenCacheItem(
		"hid",
		"env",
		"realm",
		"cid",
		"secret",
	)
	mockStorageManager.On("ReadIDToken",
		"hid",
		[]string{"env", "alias2"},
		"realm",
		"cid").Return(testIDToken, nil)
	testAppMeta := createAppMetadata("fid", "cid", "env")
	mockStorageManager.On("ReadAppMetadata", []string{"env", "alias2"}, "cid").Return(testAppMeta, nil)
	testRefreshToken := createRefreshTokenCacheItem(
		"hid",
		"env",
		"cid",
		"secret",
		"fid",
	)
	mockStorageManager.On("ReadRefreshToken",
		"hid",
		[]string{"env", "alias2"},
		"fid",
		"cid").Return(testRefreshToken, nil)
	testAccount := msalbase.NewAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")
	mockStorageManager.On("ReadAccount", "hid", []string{"env", "alias2"}, "realm").Return(testAccount, nil)
	expectedStorageToken := msalbase.CreateStorageTokenResponse(accessTokenCacheItem, testRefreshToken, testIDToken, testAccount)
	actualStorageToken, err := cacheManager.TryReadCache(authParameters, mockWebRequestManager)
	if err != nil {
		t.Errorf("Error should be nil, instead it is %v", err)
	}
	if !reflect.DeepEqual(actualStorageToken, expectedStorageToken) {
		t.Errorf("Expected storage token response %+v differs from actual storage token response %+v", expectedStorageToken, actualStorageToken)
	}
}

func TestCacheTokenResponse(t *testing.T) {
	mockStorageManager := new(MockStorageManager)
	cacheManager := &defaultCacheManager{storageManager: mockStorageManager}
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
	testRefreshToken := createRefreshTokenCacheItem(
		"testUID.testUtid",
		"env",
		"cid",
		"refreshToken",
		"fid",
	)
	mockStorageManager.On("WriteRefreshToken", testRefreshToken).Return(nil)
	accessTokenCacheItem := createAccessTokenCacheItem(
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
	mockStorageManager.On("WriteAccessToken", accessTokenCacheItem).Return(nil)
	testIDToken := createIDTokenCacheItem(
		"testUID.testUtid",
		"env",
		"realm",
		"cid",
		"idToken",
	)
	mockStorageManager.On("WriteIDToken", testIDToken).Return(nil)
	testAccount := msalbase.NewAccount("testUID.testUtid", "env", "realm", "lid", msalbase.MSSTS, "username")
	mockStorageManager.On("WriteAccount", testAccount).Return(nil)
	testAppMeta := createAppMetadata("fid", "cid", "env")
	mockStorageManager.On("WriteAppMetadata", testAppMeta).Return(nil)
	actualAccount, err := cacheManager.CacheTokenResponse(authParams, tokenResponse)
	if err != nil {
		t.Errorf("Error should be nil; instead, it is %v", err)
	}
	if !reflect.DeepEqual(actualAccount, testAccount) {
		t.Errorf("Actual account %+v differs from expected account %+v", actualAccount, testAccount)
	}
}
