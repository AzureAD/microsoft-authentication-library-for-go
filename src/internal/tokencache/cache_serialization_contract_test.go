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

var (
	defaultEnvironment = "login.windows.net"
	defaultHID         = "uid.utid"
	defaultRealm       = "contoso"
	defaultScopes      = "s2 s1 s3"
	defaultClientID    = "my_client_id"
	accessTokenCred    = msalbase.CredentialTypeOauth2AccessToken.ToString()
	accessTokenSecret  = "an access token"
	atCached           = "1000"
	atExpires          = "4600"
	rtCredType         = msalbase.CredentialTypeOauth2RefreshToken.ToString()
	rtSecret           = "a refresh token"
	idCred             = "IdToken"
	idSecret           = "header.eyJvaWQiOiAib2JqZWN0MTIzNCIsICJwcmVmZXJyZWRfdXNlcm5hbWUiOiAiSm9obiBEb2UiLCAic3ViIjogInN1YiJ9.signature"
	accUser            = "John Doe"
	accLID             = "object1234"
	accAuth            = msalbase.AuthorityTypeAad.ToString()
)

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
	if !reflect.DeepEqual(expectedAccessTokens, contract.AccessTokens) {
		t.Errorf("Expected access tokens %+v differ from actual access tokens %+v", expectedAccessTokens, contract.AccessTokens)
	}
	expectedRefreshTokens := map[string]*refreshTokenCacheItem{
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
	if !reflect.DeepEqual(expectedRefreshTokens, contract.RefreshTokens) {
		t.Errorf("Expected refresh tokens %+v differ from actual refresh tokens %+v", expectedRefreshTokens, contract.RefreshTokens)
	}

	expectedIDTokens := map[string]*idTokenCacheItem{
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
	if !reflect.DeepEqual(expectedIDTokens, contract.IDTokens) {
		t.Errorf("Expected ID tokens %+v differ from actual ID tokens %+v", expectedIDTokens, contract.IDTokens)
	}
	/*
		expectedAccounts := map[string]*msalbase.Account{
			"uid.utid-login.windows.net-contoso": {
				PreferredUsername:   &accUser,
				LocalAccountID:      &accLID,
				Realm:               &defaultRealm,
				Environment:         &defaultEnvironment,
				HomeAccountID:       &defaultHID,
				AuthorityTypeString: &accAuth,
			},
		}*/
	expectedMetadata := map[string]*AppMetadata{
		"appmetadata-login.windows.net-my_client_id": {
			Environment:      &defaultEnvironment,
			FamilyID:         nil,
			ClientID:         &defaultClientID,
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
	contract.RefreshTokens = map[string]*refreshTokenCacheItem{
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
	contract.IDTokens = map[string]*idTokenCacheItem{
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
	contract.Accounts = map[string]*msalbase.Account{
		"uid.utid-login.windows.net-contoso": {
			PreferredUsername:   &accUser,
			LocalAccountID:      &accLID,
			Realm:               &defaultRealm,
			Environment:         &defaultEnvironment,
			HomeAccountID:       &defaultHID,
			AuthorityTypeString: &accAuth,
		},
	}
	contract.AppMetadata = map[string]*AppMetadata{
		"appmetadata-login.windows.net-my_client_id": {
			Environment:      &defaultEnvironment,
			FamilyID:         nil,
			ClientID:         &defaultClientID,
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
