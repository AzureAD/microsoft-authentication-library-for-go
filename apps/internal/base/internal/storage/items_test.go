// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package storage

import (
	stdJSON "encoding/json"
	"os"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json"
	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
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
	expiresOn     = time.Unix(1592049600, 0)
	extExpiresOn  = time.Unix(1592049600, 0)
	cachedAt      = time.Unix(1592049600, 0)
	atCacheEntity = &AccessToken{
		HomeAccountID:     testHID,
		Environment:       env,
		CredentialType:    credential,
		ClientID:          clientID,
		Realm:             realm,
		Scopes:            scopes,
		Secret:            secret,
		ExpiresOn:         internalTime.Unix{T: expiresOn},
		ExtendedExpiresOn: internalTime.Unix{T: extExpiresOn},
		CachedAt:          internalTime.Unix{T: cachedAt},
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
		testCachedAt,
		testExpiresOn,
		testExtExpiresOn,
		"user.read",
		"access",
	)
	if !extExpiresOn.Equal(actualAt.ExtendedExpiresOn.T) {
		t.Errorf("Actual ext expires on %s differs from expected ext expires on %s", actualAt.ExtendedExpiresOn, extExpiresOn)
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

	want := &AccessToken{
		HomeAccountID: testHID,
		Environment:   env,
		CachedAt:      internalTime.Unix{T: time.Unix(100, 0)},
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
	accessToken := &AccessToken{
		HomeAccountID:  testHID,
		Environment:    "",
		CachedAt:       internalTime.Unix{T: time.Unix(100, 0)},
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
	testCache, err := os.ReadFile(testFile)
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
		Accounts: map[string]shared.Account{
			"uid.utid-login.windows.net-contoso": {
				PreferredUsername: "John Doe",
				LocalAccountID:    "object1234",
				Realm:             "contoso",
				Environment:       "login.windows.net",
				HomeAccountID:     "uid.utid",
				AuthorityType:     "MSSTS",
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
	rtCredential = "accesstokens.RefreshToken"
	refSecret    = "secret"
)

var rt = &accesstokens.RefreshToken{
	HomeAccountID:  hid,
	Environment:    env,
	ClientID:       rtClientID,
	CredentialType: rtCredential,
	Secret:         refSecret,
}

func TestNewRefreshToken(t *testing.T) {
	got := accesstokens.NewRefreshToken("HID", "env", "clientID", "secret", "")
	if refSecret != got.Secret {
		t.Errorf("expected secret %s differs from actualSecret %s", refSecret, got.Secret)
	}
}

func TestKeyForRefreshToken(t *testing.T) {
	want := "HID-env-accesstokens.RefreshToken-clientID"
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
	want := accesstokens.RefreshToken{
		HomeAccountID: "hid",
		Environment:   "env",
		Secret:        "secret",
		AdditionalFields: map[string]interface{}{
			"extra": json.MarshalRaw("this_is_extra"),
		},
	}

	got := accesstokens.RefreshToken{}
	err = json.Unmarshal(b, &got)
	if err != nil {
		panic(err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestRefreshTokenUnmarshal: -want/+got:\n%s", diff)
	}
}

func TestRefreshTokenMarshal(t *testing.T) {
	refreshToken := accesstokens.RefreshToken{
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
		"credential_type": "accesstokens.RefreshToken",
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

func TestRegression196(t *testing.T) {
	// https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/196

	// Note: all values here look real, but they have been altered to prevent any exposure
	// of even a temporary security value.
	contract := &Contract{
		AccessTokens: map[string]AccessToken{
			"-login.microsoftonline.com-AccessToken-5b0c5134eacb-https://graph.microsoft.com/.default": {
				HomeAccountID:     "",
				Environment:       "login.microsoftonline.com",
				Realm:             "2cce-489d-4002-8293-5b0eacb",
				CredentialType:    "AccessToken",
				ClientID:          "841-b1d2-460b-bc46-11cfb",
				Secret:            "secret",
				Scopes:            "https://graph.microsoft.com/.default",
				ExpiresOn:         internalTime.Unix{T: expiresOn},
				ExtendedExpiresOn: internalTime.Unix{T: extExpiresOn},
				CachedAt:          internalTime.Unix{T: cachedAt},
			},
		},
		AppMetaData: map[string]AppMetaData{
			"AppMetaData-login.microsoftonline.com-84a31-b1d2-460b-bc46-1158fb": {
				ClientID:    "8431-bd2-460b-bc46-11c4c8fb",
				Environment: "login.microsoftonline.com",
			},
		},
	}

	b, err := json.Marshal(contract)
	if err != nil {
		t.Fatalf("TestRegression196: Marshal had unexpected error: %v", err)
	}

	got := &Contract{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("TestRegression196: Unmarshal had unexpected error: %v, json was:\n%s", err, string(b))
	}

	if diff := pretty.Compare(contract, got); diff != "" {
		t.Fatalf("TestRegression196: -want/+got:\n%s", diff)
	}
}
