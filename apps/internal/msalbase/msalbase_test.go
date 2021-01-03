// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	stdJSON "encoding/json"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json"

	"github.com/kylelemons/godebug/pretty"
)

var (
	accHID   = "hid"
	accEnv   = "env"
	accRealm = "realm"
	authType = "MSSTS"
	accLid   = "lid"
	accUser  = "user"
)

var testAccount = Account{
	HomeAccountID:     accHID,
	PreferredUsername: accUser,
	Environment:       accEnv,
}

func TestAccountUnmarshal(t *testing.T) {
	jsonMap := map[string]interface{}{
		"home_account_id": "hid",
		"environment":     "env",
		"extra":           "this_is_extra",
		"authority_type":  authType,
	}

	b, err := stdJSON.Marshal(jsonMap)
	if err != nil {
		panic(err)
	}

	want := Account{
		HomeAccountID: accHID,
		Environment:   accEnv,
		AuthorityType: authType,
		AdditionalFields: map[string]interface{}{
			"extra": json.MarshalRaw("this_is_extra"),
		},
	}

	got := Account{}
	err = json.Unmarshal(b, &got)
	if err != nil {
		panic(err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestAccountUnmarshal: -want/+got:\n%s", diff)
	}
}

func TestAccountKey(t *testing.T) {
	acc := &Account{
		HomeAccountID: accHID,
		Environment:   accEnv,
		Realm:         accRealm,
	}
	expectedKey := "hid-env-realm"
	actualKey := acc.Key()
	if expectedKey != actualKey {
		t.Errorf("Actual key %s differs from expected key %s", actualKey, expectedKey)
	}
}

func TestAccountMarshal(t *testing.T) {
	acc := Account{
		HomeAccountID:     accHID,
		Environment:       accEnv,
		Realm:             accRealm,
		LocalAccountID:    accLid,
		AuthorityType:     authType,
		PreferredUsername: accUser,
		AdditionalFields:  map[string]interface{}{"extra": "extra"},
	}

	want := map[string]interface{}{
		"home_account_id":  "hid",
		"environment":      "env",
		"realm":            "realm",
		"local_account_id": "lid",
		"authority_type":   authType,
		"username":         "user",
		"extra":            "extra",
	}
	b, err := json.Marshal(acc)
	if err != nil {
		panic(err)
	}

	got := map[string]interface{}{}
	if err := stdJSON.Unmarshal(b, &got); err != nil {
		panic(err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestAccountMarshal: -want/+got:\n%s", diff)
	}
}

func TestGetHomeAccountIDForAccount(t *testing.T) {
	if testAccount.GetHomeAccountID() != accHID {
		t.Errorf("Actual home account ID %s differs from expected home account ID %s", testAccount.GetHomeAccountID(), accHID)
	}
}

func TestGetUsernameForAccount(t *testing.T) {
	if testAccount.GetUsername() != accUser {
		t.Errorf("Actual username %s differs from expected username %s", testAccount.GetUsername(), accUser)
	}
}

func TestGetEnvironmentForAccount(t *testing.T) {
	if testAccount.GetEnvironment() != accEnv {
		t.Errorf("Actual environment %s differs from expected environment %s", testAccount.GetEnvironment(), accEnv)
	}
}

const (
	testTokenResponse = `{
	"access_token" : "secret",
	"expires_in": 86399,
	"ext_expires_in": 86399
	}`

	testTokenResponseErrors = `{"expires_in": 86399, "ext_expires_in": 86399}`
)

func createFakeResp(code int, body string) *http.Response {
	return &http.Response{
		Body:       ioutil.NopCloser(strings.NewReader(body)),
		StatusCode: code,
	}
}

func TestCreateTokenResponse(t *testing.T) {
	scopes := []string{"openid", "profile"}
	testAuthParams := AuthParametersInternal{
		Scopes: scopes,
	}
	expiresIn := time.Now().Add(time.Second * time.Duration(86399))
	want := &TokenResponse{
		AccessToken:   "secret",
		ExpiresOn:     expiresIn,
		ExtExpiresOn:  expiresIn,
		GrantedScopes: scopes,
		ClientInfo:    ClientInfoJSONPayload{},
	}

	got, err := CreateTokenResponse(testAuthParams, createFakeResp(http.StatusOK, testTokenResponse))
	if err != nil {
		t.Errorf("TestCreateTokenResponse: got err == %v, want err == nil", err)
	}
	// Note: IncludeUnexported prevents minor differences in time.Time due to internal fields.
	if diff := (&pretty.Config{IncludeUnexported: false}).Compare(want, got); diff != "" {
		t.Errorf("TestCreateTokenResponse: -want/+got:\n%s", diff)
	}
}

func TestCreateTokenResponseWithErrors(t *testing.T) {
	scopes := []string{"openid", "profile"}
	testAuthParams := AuthParametersInternal{
		Scopes: scopes,
	}
	_, err := CreateTokenResponse(testAuthParams, createFakeResp(http.StatusOK, testTokenResponseErrors))
	if !reflect.DeepEqual(err.Error(), "response is missing access_token") {
		t.Errorf("Actual error %s differs from expected error %s",
			err.Error(), "response is missing access_token")
	}
}

func TestGetHomeAccountIDFromClientInfo(t *testing.T) {
	clientInfo := ClientInfoJSONPayload{
		UID:  "uid",
		Utid: "utid",
	}
	tokenResponse := TokenResponse{ClientInfo: clientInfo}
	expectedHid := "uid.utid"
	actualHid := tokenResponse.GetHomeAccountIDFromClientInfo()
	if !reflect.DeepEqual(actualHid, expectedHid) {
		t.Errorf("Actual home account ID %s differs from expected home account ID %s", actualHid, expectedHid)
	}
}

func TestFindDeclinedScopes(t *testing.T) {
	requestedScopes := []string{"user.read", "openid"}
	grantedScopes := []string{"user.read"}
	expectedDeclinedScopes := []string{"openid"}
	actualDeclinedScopes := findDeclinedScopes(requestedScopes, grantedScopes)
	if !reflect.DeepEqual(expectedDeclinedScopes, actualDeclinedScopes) {
		t.Errorf("Actual declined scopes %v differ from expected declined scopes %v", actualDeclinedScopes, expectedDeclinedScopes)
	}
}
