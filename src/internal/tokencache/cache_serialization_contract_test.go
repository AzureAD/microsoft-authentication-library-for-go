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

const testFile = "test_serialized_cache.json"

func TestCacheSerializationContractUnmarshalJSON(t *testing.T) {
	jsonFile, err := os.Open(testFile)
	testCache, err := ioutil.ReadAll(jsonFile)
	jsonFile.Close()
	contract := createCacheSerializationContract()
	err = contract.UnmarshalJSON(testCache)
	if err != nil {
		t.Errorf("Error is supposed to be nil, but it is %v", err)
	}
	expectedAccessTokens := map[string]*accessTokenCacheItem{
		"an-entry": {
			additionalFields: map[string]interface{}{"foo": "bar"},
		},
		"uid.utid-login.windows.net-accesstoken-my_client_id-contoso-s2 s1 s3": {
			Environment:                    "login.windows.net",
			CredentialType:                 "AccessToken",
			Secret:                         "an access token",
			Realm:                          "contoso",
			Scopes:                         "s2 s1 s3",
			ClientID:                       "my_client_id",
			CachedAt:                       "1000",
			HomeAccountID:                  "uid.utid",
			ExpiresOnUnixTimestamp:         "4600",
			ExtendedExpiresOnUnixTimestamp: "4600",
			additionalFields:               make(map[string]interface{}),
		},
	}
	if !reflect.DeepEqual(expectedAccessTokens, contract.AccessTokens) {
		t.Errorf("Expected access tokens %+v differ from actual access tokens %+v", expectedAccessTokens, contract.AccessTokens)
	}
	expectedRefreshTokens := map[string]*refreshTokenCacheItem{
		"uid.utid-login.windows.net-refreshtoken-my_client_id--s2 s1 s3": {
			Target:           "s2 s1 s3",
			Environment:      "login.windows.net",
			CredentialType:   "RefreshToken",
			Secret:           "a refresh token",
			ClientID:         "my_client_id",
			HomeAccountID:    "uid.utid",
			additionalFields: make(map[string]interface{}),
		},
	}
	if !reflect.DeepEqual(expectedRefreshTokens, contract.RefreshTokens) {
		t.Errorf("Expected refresh tokens %+v differ from actual refresh tokens %+v", expectedRefreshTokens, contract.RefreshTokens)
	}
	expectedIDTokens := map[string]*idTokenCacheItem{
		"uid.utid-login.windows.net-idtoken-my_client_id-contoso-": {
			Realm:            "contoso",
			Environment:      "login.windows.net",
			CredentialType:   "IdToken",
			Secret:           "header.eyJvaWQiOiAib2JqZWN0MTIzNCIsICJwcmVmZXJyZWRfdXNlcm5hbWUiOiAiSm9obiBEb2UiLCAic3ViIjogInN1YiJ9.signature",
			ClientID:         "my_client_id",
			HomeAccountID:    "uid.utid",
			additionalFields: make(map[string]interface{}),
		},
	}
	if !reflect.DeepEqual(expectedIDTokens, contract.IDTokens) {
		t.Errorf("Expected ID tokens %+v differ from actual ID tokens %+v", expectedIDTokens, contract.IDTokens)
	}
	expectedAccounts := map[string]*msalbase.Account{
		"uid.utid-login.windows.net-contoso": {
			PreferredUsername: "John Doe",
			LocalAccountID:    "object1234",
			Realm:             "contoso",
			Environment:       "login.windows.net",
			HomeAccountID:     "uid.utid",
			AuthorityType:     msalbase.AuthorityTypeAad,
			AdditionalFields:  make(map[string]interface{}),
		},
	}
	if !reflect.DeepEqual(expectedAccounts, contract.Accounts) {
		t.Errorf("Expected accounts %+v differ from actual accounts %+v", expectedAccounts, contract.Accounts)
	}
	expectedMetadata := map[string]*AppMetadata{
		"appmetadata-login.windows.net-my_client_id": {
			Environment:      "login.windows.net",
			FamilyID:         "",
			ClientID:         "my_client_id",
			additionalFields: make(map[string]interface{}),
		},
	}
	if !reflect.DeepEqual(expectedMetadata, contract.AppMetadata) {
		t.Errorf("Expected app metadatas %+v differ from actual app metadatas %+v", expectedMetadata, contract.AppMetadata)
	}
	extraEntry := map[string]interface{}{"field1": "1", "field2": "whats"}
	expectedSnapshot := map[string]interface{}{
		"unknownEntity": extraEntry,
	}
	if !reflect.DeepEqual(expectedSnapshot, contract.snapshot) {
		t.Errorf("Expected snapshot %+v differs from actual snapshot %+v", expectedSnapshot, contract.snapshot)
	}
}

func TestCacheSerializationContractMarshalJSON(t *testing.T) {
	contract := &cacheSerializationContract{}
	contract.AccessTokens = map[string]*accessTokenCacheItem{
		"an-entry": {
			additionalFields: map[string]interface{}{"foo": "bar"},
		},
		"uid.utid-login.windows.net-accesstoken-my_client_id-contoso-s2 s1 s3": {
			Environment:                    "login.windows.net",
			CredentialType:                 "AccessToken",
			Secret:                         "an access token",
			Realm:                          "contoso",
			Scopes:                         "s2 s1 s3",
			ClientID:                       "my_client_id",
			CachedAt:                       "1000",
			HomeAccountID:                  "uid.utid",
			ExpiresOnUnixTimestamp:         "4600",
			ExtendedExpiresOnUnixTimestamp: "4600",
			additionalFields:               make(map[string]interface{}),
		},
	}
	contract.RefreshTokens = map[string]*refreshTokenCacheItem{
		"uid.utid-login.windows.net-refreshtoken-my_client_id--s2 s1 s3": {
			Target:           "s2 s1 s3",
			Environment:      "login.windows.net",
			CredentialType:   "RefreshToken",
			Secret:           "a refresh token",
			ClientID:         "my_client_id",
			HomeAccountID:    "uid.utid",
			additionalFields: make(map[string]interface{}),
		},
	}
	contract.IDTokens = map[string]*idTokenCacheItem{
		"uid.utid-login.windows.net-idtoken-my_client_id-contoso-": {
			Realm:            "contoso",
			Environment:      "login.windows.net",
			CredentialType:   "IdToken",
			Secret:           "header.eyJvaWQiOiAib2JqZWN0MTIzNCIsICJwcmVmZXJyZWRfdXNlcm5hbWUiOiAiSm9obiBEb2UiLCAic3ViIjogInN1YiJ9.signature",
			ClientID:         "my_client_id",
			HomeAccountID:    "uid.utid",
			additionalFields: make(map[string]interface{}),
		},
	}
	contract.Accounts = map[string]*msalbase.Account{
		"uid.utid-login.windows.net-contoso": {
			PreferredUsername: "John Doe",
			LocalAccountID:    "object1234",
			Realm:             "contoso",
			Environment:       "login.windows.net",
			HomeAccountID:     "uid.utid",
			AuthorityType:     msalbase.AuthorityTypeAad,
			AdditionalFields:  make(map[string]interface{}),
		},
	}
	contract.AppMetadata = map[string]*AppMetadata{
		"appmetadata-login.windows.net-my_client_id": {
			Environment:      "login.windows.net",
			FamilyID:         "",
			ClientID:         "my_client_id",
			additionalFields: make(map[string]interface{}),
		},
	}
	extraEntry := map[string]interface{}{"field1": "1", "field2": "whats"}
	contract.snapshot = map[string]interface{}{
		"unknownEntity": extraEntry,
	}
	_, err := contract.MarshalJSON()
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}
