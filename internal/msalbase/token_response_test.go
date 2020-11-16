// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"reflect"
	"testing"
	"time"
)

var testTokenResponse = `{
	"access_token" : "secret",
	"expires_in": 86399,
	"ext_expires_in": 86399
	}`

func TestCreateTokenResponse(t *testing.T) {
	scopes := []string{"openid", "profile"}
	testAuthParams := AuthParametersInternal{
		Scopes: scopes,
	}
	expiresIn := time.Now().Add(time.Second * time.Duration(86399))
	expTokenResponse := &TokenResponse{
		baseResponse:  OAuthResponseBase{},
		AccessToken:   "secret",
		ExpiresOn:     expiresIn,
		ExtExpiresOn:  expiresIn,
		GrantedScopes: scopes,
		ClientInfo:    ClientInfoJSONPayload{},
	}
	actualTokenResp, err := CreateTokenResponse(testAuthParams, 200, testTokenResponse)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(expTokenResponse.baseResponse, actualTokenResp.baseResponse) &&
		!reflect.DeepEqual(expTokenResponse.AccessToken, actualTokenResp.AccessToken) &&
		!reflect.DeepEqual(expTokenResponse.ExpiresOn, actualTokenResp.ExpiresOn) &&
		!reflect.DeepEqual(expTokenResponse.ExtExpiresOn, actualTokenResp.ExtExpiresOn) &&
		!reflect.DeepEqual(expTokenResponse.GrantedScopes, actualTokenResp.GrantedScopes) &&
		!reflect.DeepEqual(expTokenResponse.ClientInfo, actualTokenResp.ClientInfo) {
		t.Errorf("Expected token response %+v differs from actual token response %+v", expTokenResponse, actualTokenResp)
	}
}

func TestCreateTokenResponseWithErrors(t *testing.T) {
	scopes := []string{"openid", "profile"}
	testAuthParams := AuthParametersInternal{
		Scopes: scopes,
	}
	testTokenResponseErrors := `{"expires_in": 86399, "ext_expires_in": 86399}`
	_, err := CreateTokenResponse(testAuthParams, 200, testTokenResponseErrors)
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
