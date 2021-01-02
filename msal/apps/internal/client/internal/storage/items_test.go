// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package storage

import (
	stdJSON "encoding/json"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/json"
	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/apps/internal/msalbase"
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
	atCacheEntity = &AccessToken{
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

func TestCreateAccessToken(t *testing.T) {
	testExpiresOn := time.Date(2020, time.June, 13, 12, 0, 0, 0, time.UTC)
	testExtExpiresOn := time.Date(2020, time.June, 13, 12, 0, 0, 0, time.UTC)
	testCachedAt := time.Date(2020, time.June, 13, 11, 0, 0, 0, time.UTC)
	actualAt := NewAccessToken("testHID",
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

func TestKeyForAccessToken(t *testing.T) {
	const want = "testHID-env-AccessToken-clientID-realm-user.read"
	got := atCacheEntity.Key()
	if got != want {
		t.Errorf("TestKeyForAccessToken: got %s, want %s", got, want)
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
	want := &AccessToken{
		HomeAccountID: testHID,
		Environment:   env,
		CachedAt:      testCachedAt,
		AdditionalFields: map[string]interface{}{
			"extra": json.MarshalRaw("this_is_extra"),
		},
	}
	got := &AccessToken{}
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
	accessToken := &AccessToken{
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
	got := AccessToken{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("TestAccessTokenMarshal: unable to take JSON byte output and unmarshal: %s", err)
	}

	if diff := pretty.Compare(accessToken, got); diff != "" {
		t.Errorf("TestAccessTokenConvertToJSONMap(access token): -want/+got:\n%s", diff)
	}
}

var (
	appClient = "cid"
	appEnv    = "env"
	appMeta   = &AppMetaData{
		ClientID:    appClient,
		Environment: appEnv,
		FamilyID:    "",
	}
)

func TestKeyForAppMetaData(t *testing.T) {
	want := "AppMetaData-env-cid"
	got := appMeta.Key()
	if want != got {
		t.Errorf("actual key %v differs from expected key %v", want, got)
	}
}

func TestAppMetaDataUnmarshal(t *testing.T) {
	jsonMap := map[string]interface{}{
		"environment": "env",
		"extra":       "this_is_extra",
		"cached_at":   "100",
		"client_id":   "cid",
		"family_id":   nil,
	}
	want := AppMetaData{
		ClientID:    "cid",
		Environment: "env",
		AdditionalFields: map[string]interface{}{
			"extra":     json.MarshalRaw("this_is_extra"),
			"cached_at": json.MarshalRaw("100"),
		},
	}

	b, err := stdJSON.Marshal(jsonMap)
	if err != nil {
		panic(err)
	}
	got := AppMetaData{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("TestAppMetaDataUnmarshal(unmarshal): got err == %s, want err == nil", err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Fatalf("TestAppMetaDataUnmarshal: -want/+got:\n%s", diff)
	}
}

func TestAppMetaDataMarshal(t *testing.T) {
	AppMetaData := AppMetaData{
		Environment: "",
		ClientID:    appClient,
		FamilyID:    "",
		AdditionalFields: map[string]interface{}{
			"extra":     "this_is_extra",
			"cached_at": "100",
		},
	}

	want := map[string]interface{}{
		"client_id": "cid",
		"extra":     "this_is_extra",
		"cached_at": "100",
	}

	b, err := json.Marshal(AppMetaData)
	if err != nil {
		panic(err)
	}
	got := map[string]interface{}{}
	if err := stdJSON.Unmarshal(b, &got); err != nil {
		t.Fatalf("TestAppMetaDataMarshal(unmarshal): err == %s, want err == nil", err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestAppMetaDataConvertToJSONMap: -want/+got:\n%s", diff)
	}
}

func TestContractUnmarshalJSON(t *testing.T) {
	jsonFile, err := os.Open(testFile)
	if err != nil {
		panic(err)
	}
	defer jsonFile.Close()

	testCache, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		panic(err)
	}

	got := Contract{}
	err = json.Unmarshal(testCache, &got)
	if err != nil {
		t.Fatalf("TestContractUnmarshalJSON(unmarshal): %v", err)
	}

	want := Contract{
		AccessTokens: map[string]AccessToken{
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
		AppMetaData: map[string]AppMetaData{
			"AppMetadata-login.windows.net-my_client_id": {
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
		t.Errorf("TestContractUnmarshalJSON: -want/+got:\n%s", diff)
		t.Errorf(string(got.AdditionalFields["unknownEntity"].(stdJSON.RawMessage)))
	}
}

func TestContractMarshalJSON(t *testing.T) {
	want := Contract{
		AccessTokens: map[string]AccessToken{
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
		t.Fatalf("TestContractMarshalJSON(marshal): got err == %s, want err == nil", err)
	}
	got := Contract{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("TestContractMarshalJSON(unmarshal back): got err == %s, want err == nil", err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestContractMarshalJSON: -want/+got:\n%s", diff)
	}
}

var (
	idHid        = "HID"
	idEnv        = "env"
	idCredential = "IdToken"
	idClient     = "clientID"
	idRealm      = "realm"
	idTokSecret  = "id"
)

var idToken = IDToken{
	HomeAccountID:  idHid,
	Environment:    idEnv,
	CredentialType: idCredential,
	ClientID:       idClient,
	Realm:          idRealm,
	Secret:         idTokSecret,
}

func TestKeyForIDToken(t *testing.T) {
	want := "HID-env-IdToken-clientID-realm"
	if idToken.Key() != want {
		t.Errorf("actual key %v differs from expected key %v", idToken.Key(), want)
	}
}

func TestIDTokenUnmarshal(t *testing.T) {
	jsonMap := map[string]interface{}{
		"home_account_id": "HID",
		"environment":     "env",
		"extra":           "this_is_extra",
	}
	b, err := stdJSON.Marshal(jsonMap)
	if err != nil {
		panic(err)
	}

	want := IDToken{
		HomeAccountID: "HID",
		Environment:   "env",
		AdditionalFields: map[string]interface{}{
			"extra": json.MarshalRaw("this_is_extra"),
		},
	}

	got := IDToken{}
	if err := json.Unmarshal(b, &got); err != nil {
		panic(err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestIDTokenUnmarshal: -want/+got:\n%s", diff)
	}
}

func TestIDTokenMarshal(t *testing.T) {
	idToken := IDToken{
		HomeAccountID:    idHid,
		Environment:      idEnv,
		Realm:            "",
		AdditionalFields: map[string]interface{}{"extra": "this_is_extra"},
	}

	want := map[string]interface{}{
		"home_account_id": "HID",
		"environment":     "env",
		"extra":           "this_is_extra",
	}

	b, err := json.Marshal(idToken)
	if err != nil {
		panic(err)
	}
	got := map[string]interface{}{}

	if err := stdJSON.Unmarshal(b, &got); err != nil {
		panic(err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestIDTokenMarshal: -want/+got:\n%s", diff)
	}
}

var (
	hid          = "HID"
	rtEnv        = "env"
	rtClientID   = "clientID"
	rtCredential = "RefreshToken"
	refSecret    = "secret"
)

var rt = &RefreshToken{
	HomeAccountID:  hid,
	Environment:    env,
	ClientID:       rtClientID,
	CredentialType: rtCredential,
	Secret:         refSecret,
}

func TestNewRefreshToken(t *testing.T) {
	got := NewRefreshToken("HID", "env", "clientID", "secret", "")
	if refSecret != got.Secret {
		t.Errorf("expected secret %s differs from actualSecret %s", refSecret, got.Secret)
	}
}

func TestKeyForRefreshToken(t *testing.T) {
	want := "HID-env-RefreshToken-clientID"
	got := rt.Key()
	if want != got {
		t.Errorf("Actual key %v differs from expected key %v", got, want)
	}
}

func TestRefreshTokenUnmarshal(t *testing.T) {
	jsonMap := map[string]interface{}{
		"home_account_id": "hid",
		"environment":     "env",
		"extra":           "this_is_extra",
		"secret":          "secret",
	}
	b, err := stdJSON.Marshal(jsonMap)
	if err != nil {
		panic(err)
	}
	want := RefreshToken{
		HomeAccountID: "hid",
		Environment:   "env",
		Secret:        "secret",
		AdditionalFields: map[string]interface{}{
			"extra": json.MarshalRaw("this_is_extra"),
		},
	}

	got := RefreshToken{}
	err = json.Unmarshal(b, &got)
	if err != nil {
		panic(err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestRefreshTokenUnmarshal: -want/+got:\n%s", diff)
	}
}

func TestRefreshTokenMarshal(t *testing.T) {
	refreshToken := RefreshToken{
		HomeAccountID:  "",
		Environment:    rtEnv,
		CredentialType: rtCredential,
		Secret:         refSecret,
		AdditionalFields: map[string]interface{}{
			"extra": "this_is_extra",
		},
	}
	want := map[string]interface{}{
		"environment":     "env",
		"credential_type": "RefreshToken",
		"secret":          "secret",
		"extra":           "this_is_extra",
	}
	b, err := json.Marshal(refreshToken)
	if err != nil {
		panic(err)
	}
	got := map[string]interface{}{}

	if err := stdJSON.Unmarshal(b, &got); err != nil {
		panic(err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestRefreshTokenMarshal: -want/+got:\n%s", diff)
	}
}
