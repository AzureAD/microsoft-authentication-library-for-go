// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"reflect"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
)

var (
	testURLAuthorityInfo, _ = msalbase.CreateAuthorityInfoFromAuthorityURI("https://login.microsoftonline.com/v2.0/", true)
	testURLAuthParams       = msalbase.CreateAuthParametersInternal("clientID", testURLAuthorityInfo)
	urlWRM                  = new(requests.MockWebRequestManager)
	authCodeURLParams       = CreateAuthorizationCodeURLParameters("clientID", "redirect", []string{"openid", "user.read"})
)

func TestGetSeparatedScopes(t *testing.T) {
	expectedScopes := "openid user.read"
	actualSpaceSepScopes := authCodeURLParams.getSeparatedScopes()
	if !reflect.DeepEqual(actualSpaceSepScopes, expectedScopes) {
		t.Errorf("Actual separated scopes %v differs from expected space separated scopes %v", actualSpaceSepScopes, expectedScopes)
	}
}

func TestCreateURL(t *testing.T) {
	authCodeURLParams.CodeChallenge = "codeChallenge"
	tdr := &requests.TenantDiscoveryResponse{
		AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
		TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
		Issuer:                "https://login.microsoftonline.com/v2.0",
	}
	urlWRM.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	url, err := authCodeURLParams.createURL(urlWRM, testURLAuthParams)
	if err != nil {
		t.Errorf("Error is supposed to be nil, instead it is %v", err)
	}
	actualURL := "https://login.microsoftonline.com/v2.0/authorize?client_id=clientID&code_challenge=codeChallenge" +
		"&redirect_uri=redirect&response_type=code&scope=openid+user.read"
	if !reflect.DeepEqual(url, actualURL) {
		t.Errorf("Actual URL %v differs from expected URL %v", actualURL, url)
	}
}
