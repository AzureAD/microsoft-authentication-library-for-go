// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	stdJSON "encoding/json"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/json"
	"github.com/kylelemons/godebug/pretty"
)

var (
	testHID       = "testHID"
	env           = "env"
	credential    = "AccessToken"
	clientID      = "clientID"
	realm         = "realm"
	scopes        = "user.read"
	secret        = "access"
	expiresOn     = "1592049600"
	extExpiresOn  = "1592049600"
	cachedAt      = "1592049600"
	atCacheEntity = &accessTokenCacheItem{
		HomeAccountID:                  testHID,
		Environment:                    env,
		CredentialType:                 credential,
		ClientID:                       clientID,
		Realm:                          realm,
		Scopes:                         scopes,
		Secret:                         secret,
		ExpiresOnUnixTimestamp:         expiresOn,
		ExtendedExpiresOnUnixTimestamp: extExpiresOn,
		CachedAt:                       cachedAt,
	}
)

func TestCreateAccessTokenCacheItem(t *testing.T) {
	testExpiresOn := time.Date(2020, time.June, 13, 12, 0, 0, 0, time.UTC)
	testExtExpiresOn := time.Date(2020, time.June, 13, 12, 0, 0, 0, time.UTC)
	testCachedAt := time.Date(2020, time.June, 13, 11, 0, 0, 0, time.UTC)
	actualAt := createAccessTokenCacheItem("testHID",
		"env",
		"realm",
		"clientID",
		testCachedAt.Unix(),
		testExpiresOn.Unix(),
		testExtExpiresOn.Unix(),
		"user.read",
		"access",
	)
	if extExpiresOn != actualAt.ExtendedExpiresOnUnixTimestamp {
		t.Errorf("Actual ext expires on %s differs from expected ext expires on %s", actualAt.ExtendedExpiresOnUnixTimestamp, extExpiresOn)
	}
}

func TestCreateKeyForAccessToken(t *testing.T) {
	const want = "testHID-env-AccessToken-clientID-realm-user.read"
	got := atCacheEntity.CreateKey()
	if got != want {
		t.Errorf("TestCreateKeyForAccessToken: got %s, want %s", got, want)
	}
}

func TestAccessTokenUnmarshal(t *testing.T) {
	jsonMap := map[string]interface{}{
		"home_account_id": "testHID",
		"environment":     "env",
		"extra":           "this_is_extra",
		"cached_at":       "100",
	}
	jsonData, err := stdJSON.Marshal(jsonMap)
	if err != nil {
		panic(err)
	}

	testCachedAt := "100"
	want := &accessTokenCacheItem{
		HomeAccountID: testHID,
		Environment:   env,
		CachedAt:      testCachedAt,
		AdditionalFields: map[string]interface{}{
			"extra": json.MarshalRaw("this_is_extra"),
		},
	}
	got := &accessTokenCacheItem{}
	err = json.Unmarshal(jsonData, got)
	if err != nil {
		t.Errorf("Error is supposed to be nil, but it is %v", err)
	}
	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestAccessTokenUnmarshal(access tokens): -want/+got:\n %s", diff)
	}
}

func TestAccessTokenMarshal(t *testing.T) {
	testCachedAt := "100"
	accessToken := &accessTokenCacheItem{
		HomeAccountID:  testHID,
		Environment:    "",
		CachedAt:       testCachedAt,
		CredentialType: credential,
		AdditionalFields: map[string]interface{}{
			"extra": json.MarshalRaw("this_is_extra"),
		},
	}
	b, err := json.Marshal(accessToken)
	if err != nil {
		t.Fatalf("TestAccessTokenMarshal: unable to marshal: %s", err)
	}
	got := accessTokenCacheItem{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("TestAccessTokenMarshal: unable to take JSON byte output and unmarshal: %s", err)
	}

	if diff := pretty.Compare(accessToken, got); diff != "" {
		t.Errorf("TestAccessTokenConvertToJSONMap(access token): -want/+got:\n%s", diff)
	}
}
