// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"reflect"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
)

func TestIsAccessTokenValid(t *testing.T) {
	/*
		accessTokenCacheItem := CreateAccessTokenCacheItem(
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
		validity := isAccessTokenValid(accessTokenCacheItem)
		if !validity {
			t.Errorf("Access token should be valid")
		}
		expiresOn := strconv.FormatInt(time.Now().Unix()+200, 10)
		accessTokenCacheItem.ExpiresOnUnixTimestamp = &expiresOn
		validity = isAccessTokenValid(accessTokenCacheItem)
		if validity {
			t.Errorf("Access token shouldn't be valid")
		}
		accessTokenCacheItem.ExpiresOnUnixTimestamp = "TIMESTAMP_SHOULD_BE_INT"
		validity = isAccessTokenValid(accessTokenCacheItem)
		if validity {
			t.Errorf("Access token shouldn't be valid")
		}
		accessTokenCacheItem.CachedAt = "TIMESTAMP_SHOULD_BE_INT"
		validity = isAccessTokenValid(accessTokenCacheItem)
		if validity {
			t.Errorf("Access token shouldn't be valid")
		}
		accessTokenCacheItem.CachedAt = strconv.FormatInt(time.Now().Unix()+500, 10)
		validity = isAccessTokenValid(accessTokenCacheItem)
		if validity {
			t.Errorf("Access token shouldn't be valid")
		}
	*/
}

func TestGetAllAccounts(t *testing.T) {
	/*
		account1 := &msalbase.Account{
			HomeAccountID: "hid",
			Environment:   "env",
			Realm:         "realm",
		}
		account2 := &msalbase.Account{
			HomeAccountID: "testHID",
			Environment:   "testEnv",
			Realm:         "testRealm",
		}
		expectedAccounts := []*msalbase.Account{account1, account2}
		mockStorageManager := new(MockStorageManager)
		cacheManager := &cacheManager{storageManager: mockStorageManager}
		mockStorageManager.On("ReadAllAccounts").Return(expectedAccounts)
		actualAccounts := cacheManager.GetAllAccounts()
		if !reflect.DeepEqual(expectedAccounts, actualAccounts) {
			t.Errorf("Expected accounts %v differ from actual accounts %v", expectedAccounts, actualAccounts)
		}*/
}

func TestTryReadCache(t *testing.T) {
	mockStorageManager := new(MockStorageManager)
	mockWebRequestManager := new(requests.MockWebRequestManager)
	cacheManager := &cacheManager{storageManager: mockStorageManager}
	authInfo := &msalbase.AuthorityInfo{
		Host:               "env",
		UserRealmURIPrefix: "realm",
	}
	authParameters := &msalbase.AuthParametersInternal{
		HomeaccountID: "hid",
		AuthorityInfo: authInfo,
		ClientID:      "cid",
		Scopes:        []string{"openid", "profile"},
	}
	metadata1 := &requests.InstanceDiscoveryMetadata{
		Aliases: []string{"env", "alias2"},
	}
	metadata2 := &requests.InstanceDiscoveryMetadata{
		Aliases: []string{"alias3", "alias4"},
	}
	metadata := []*requests.InstanceDiscoveryMetadata{metadata1, metadata2}
	mockInstDiscResponse := &requests.InstanceDiscoveryResponse{
		TenantDiscoveryEndpoint: "tenant",
		Metadata:                metadata,
	}
	mockWebRequestManager.On("GetAadinstanceDiscoveryResponse", authInfo).Return(mockInstDiscResponse, nil)
	accessTokenCacheItem := CreateAccessTokenCacheItem(
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
		[]string{"openid", "profile"}).Return(accessTokenCacheItem)
	testIDToken := CreateIDTokenCacheItem(
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
		"cid").Return(testIDToken)
	testAppMeta := CreateAppMetadata("fid", "cid", "env")
	mockStorageManager.On("ReadAppMetadata", []string{"env", "alias2"}, "cid").Return(testAppMeta)
	testRefreshToken := CreateRefreshTokenCacheItem(
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
		"cid").Return(testRefreshToken)
	testAccount := msalbase.CreateAccount("hid", "env", "realm", "lid", msalbase.AuthorityTypeAad, "username")
	mockStorageManager.On("ReadAccount", "hid", []string{"env", "alias2"}, "realm").Return(testAccount)
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
	cacheManager := &cacheManager{storageManager: mockStorageManager}
	clientInfo := &msalbase.ClientInfoJSONPayload{
		UID:  "testUID",
		Utid: "testUtid",
	}
	idToken := &msalbase.IDToken{
		RawToken:          "idToken",
		Oid:               "lid",
		PreferredUsername: "username",
	}
	expiresOn := time.Unix(time.Now().Unix()+1000, 0).UTC()
	tokenResponse := &msalbase.TokenResponse{
		AccessToken:   "accessToken",
		RefreshToken:  "refreshToken",
		IDToken:       idToken,
		FamilyID:      "fid",
		ClientInfo:    clientInfo,
		GrantedScopes: []string{"openid", "profile"},
		ExpiresOn:     expiresOn,
		ExtExpiresOn:  time.Now(),
	}
	authInfo := &msalbase.AuthorityInfo{Host: "env", UserRealmURIPrefix: "realm", AuthorityType: msalbase.AuthorityTypeAad}
	authParams := &msalbase.AuthParametersInternal{
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
	mockStorageManager.On("WriteRefreshToken", testRefreshToken).Return(nil)
	accessTokenCacheItem := CreateAccessTokenCacheItem(
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
	testIDToken := CreateIDTokenCacheItem(
		"testUID.testUtid",
		"env",
		"realm",
		"cid",
		"idToken",
	)
	mockStorageManager.On("WriteIDToken", testIDToken).Return(nil)
	testAccount := msalbase.CreateAccount("testUID.testUtid", "env", "realm", "lid", msalbase.AuthorityTypeAad, "username")
	mockStorageManager.On("WriteAccount", testAccount).Return(nil)
	testAppMeta := CreateAppMetadata("fid", "cid", "env")
	mockStorageManager.On("WriteAppMetadata", testAppMeta).Return(nil)
	actualAccount, err := cacheManager.CacheTokenResponse(authParams, tokenResponse)
	if err != nil {
		t.Errorf("Error should be nil; instead, it is %v", err)
	}
	if !reflect.DeepEqual(actualAccount, testAccount) {
		t.Errorf("Actual account %+v differs from expected account %+v", actualAccount, testAccount)
	}
}
