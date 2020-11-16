// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	stdJSON "encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/json"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/kylelemons/godebug/pretty"
)

const testFile = "test_serialized_cache.json"

var (
	defaultEnvironment = "login.windows.net"
	defaultHID         = "uid.utid"
	defaultRealm       = "contoso"
	defaultScopes      = "s2 s1 s3"
	defaultClientID    = "my_client_id"
	accessTokenCred    = msalbase.CredentialTypeAccessToken
	accessTokenSecret  = "an access token"
	atCached           = "1000"
	atExpires          = "4600"
	rtCredType         = msalbase.CredentialTypeRefreshToken
	rtSecret           = "a refresh token"
	idCred             = "IdToken"
	idSecret           = "header.eyJvaWQiOiAib2JqZWN0MTIzNCIsICJwcmVmZXJyZWRfdXNlcm5hbWUiOiAiSm9obiBEb2UiLCAic3ViIjogInN1YiJ9.signature"
	accUser            = "John Doe"
	accLID             = "object1234"
	accAuth            = string(msalbase.MSSTS)
)

func TestCacheSerializationContractUnmarshalJSON(t *testing.T) {
	jsonFile, err := os.Open(testFile)
	if err != nil {
		panic(err)
	}
	defer jsonFile.Close()

	testCache, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		panic(err)
	}

	got := cacheSerializationContract{}
	err = json.Unmarshal(testCache, &got)
	if err != nil {
		t.Fatalf("TestCacheSerializationContractUnmarshalJSON(unmarshal): %v", err)
	}

	want := cacheSerializationContract{
		AccessTokens: map[string]accessTokenCacheItem{
			"an-entry": {
				AdditionalFields: map[string]interface{}{
					"foo": json.MarshalRaw("bar"),
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
		Accounts: map[string]msalbase.Account{
			"uid.utid-login.windows.net-contoso": {
				PreferredUsername: "John Doe",
				LocalAccountID:    "object1234",
				Realm:             "contoso",
				Environment:       "login.windows.net",
				HomeAccountID:     "uid.utid",
				AuthorityType:     "MSSTS",
			},
		},
		RefreshTokens: map[string]refreshTokenCacheItem{
			"uid.utid-login.windows.net-refreshtoken-my_client_id--s2 s1 s3": {
				Target:         defaultScopes,
				Environment:    defaultEnvironment,
				CredentialType: rtCredType,
				Secret:         rtSecret,
				ClientID:       defaultClientID,
				HomeAccountID:  defaultHID,
			},
		},
		IDTokens: map[string]idTokenCacheItem{
			"uid.utid-login.windows.net-idtoken-my_client_id-contoso-": {
				Realm:          defaultRealm,
				Environment:    defaultEnvironment,
				CredentialType: idCred,
				Secret:         idSecret,
				ClientID:       defaultClientID,
				HomeAccountID:  defaultHID,
			},
		},
		AppMetadata: map[string]appMetadata{
			"appmetadata-login.windows.net-my_client_id": {
				Environment: defaultEnvironment,
				FamilyID:    "",
				ClientID:    defaultClientID,
			},
		},
		AdditionalFields: map[string]interface{}{
			"unknownEntity": json.MarshalRaw(
				map[string]interface{}{
					"field1": "1",
					"field2": "whats",
				},
			),
		},
	}
	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestCacheSerializationContractUnmarshalJSON: -want/+got:\n%s", diff)
		t.Errorf(string(got.AdditionalFields["unknownEntity"].(stdJSON.RawMessage)))
	}
}

func TestCacheSerializationContractMarshalJSON(t *testing.T) {
	want := cacheSerializationContract{
		AccessTokens: map[string]accessTokenCacheItem{
			"an-entry": {
				AdditionalFields: map[string]interface{}{
					"foo": json.MarshalRaw("bar"),
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
		RefreshTokens: map[string]refreshTokenCacheItem{
			"uid.utid-login.windows.net-refreshtoken-my_client_id--s2 s1 s3": {
				Target:         defaultScopes,
				Environment:    defaultEnvironment,
				CredentialType: rtCredType,
				Secret:         rtSecret,
				ClientID:       defaultClientID,
				HomeAccountID:  defaultHID,
			},
		},
		IDTokens: map[string]idTokenCacheItem{
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
		AppMetadata: map[string]appMetadata{
			"appmetadata-login.windows.net-my_client_id": {
				Environment: defaultEnvironment,
				FamilyID:    "",
				ClientID:    defaultClientID,
			},
		},
		AdditionalFields: map[string]interface{}{
			"unknownEntity": json.MarshalRaw(
				map[string]interface{}{
					"field1": "1",
					"field2": "whats",
				},
			),
		},
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("TestCacheSerializationContractMarshalJSON(marshal): got err == %s, want err == nil", err)
	}
	got := cacheSerializationContract{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("TestCacheSerializationContractMarshalJSON(unmarshal back): got err == %s, want err == nil", err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestCacheSerializationContractMarshalJSON: -want/+got:\n%s", diff)
	}
}
