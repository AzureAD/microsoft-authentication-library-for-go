// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"reflect"
	"testing"
)

func TestCreateTokenResponse(t *testing.T) {

}

func TestGetHomeAccountIDFromClientInfo(t *testing.T) {
	clientInfo := &ClientInfoJSONPayload{
		UID:  "uid",
		Utid: "utid",
	}
	tokenResponse := &TokenResponse{ClientInfo: clientInfo}
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
