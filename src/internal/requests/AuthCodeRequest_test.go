// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"reflect"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/tokencache"
)

var testAuthorityEndpoints = msalbase.CreateAuthorityEndpoints("https://login.microsoftonline.com/v2.0/authorize",
	"https://login.microsoftonline.com/v2.0/token",
	"https://login.microsoftonline.com/v2.0",
	"https://login.microsoftonline.com")
var testAuthorityInfo, err = msalbase.CreateAuthorityInfoFromAuthorityUri("https://login.microsoftonline.com/v2.0/", true)
var testAuthParams = msalbase.CreateAuthParametersInternal("clientID", testAuthorityInfo)
var testAuthCodeURLParams = msalbase.CreateAuthorizationCodeURLParameters(testAuthParams, "codeChallenge")

var wrm = new(MockWebRequestManager)

var authCodeRequest = &AuthCodeRequest{
	webRequestManager:     wrm,
	cacheManager:          new(tokencache.MockCacheManager),
	authParameters:        testAuthParams,
	authCodeURLParameters: testAuthCodeURLParams,
	code:                  "code",
	codeChallenge:         "codeChallenge",
}

func TestBuildURL(t *testing.T) {
	testAuthParams.SetAuthorityEndpoints(testAuthorityEndpoints)
	testAuthParams.SetRedirectURI("http://localhost:3000/redirect")
	testAuthParams.SetScopes([]string{"openid", "user.read"})
	url, err := authCodeRequest.buildURL()
	if err != nil {
		t.Errorf("Error is supposed to be nil, instead it is %v", err)
	}
	actualURL := "https://login.microsoftonline.com/v2.0/authorize?client_id=clientID&code_challenge=codeChallenge" +
		"&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fredirect&response_type=code&scope=openid+user.read"
	if !reflect.DeepEqual(url, actualURL) {
		t.Errorf("Actual URL %v differs from expected URL %v", actualURL, url)
	}
}

func TestGetURL(t *testing.T) {
	testAuthParams.SetRedirectURI("http://localhost:3000/redirect")
	testAuthParams.SetScopes([]string{"openid", "user.read"})
	tdr := &TenantDiscoveryResponse{
		AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
		TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
		Issuer:                "https://login.microsoftonline.com/v2.0",
	}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	url, err := authCodeRequest.GetAuthURL()
	if err != nil {
		t.Errorf("Error is supposed to be nil, instead it is %v", err)
	}
	actualURL := "https://login.microsoftonline.com/v2.0/authorize?client_id=clientID&code_challenge=codeChallenge" +
		"&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fredirect&response_type=code&scope=openid+user.read"
	if !reflect.DeepEqual(url, actualURL) {
		t.Errorf("Actual URL %v differs from expected URL %v", actualURL, url)
	}
}

func TestAuthCodeReqExecute(t *testing.T) {
	tdr := &TenantDiscoveryResponse{
		AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
		TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
		Issuer:                "https://login.microsoftonline.com/v2.0",
	}
	actualTokenResp := &msalbase.TokenResponse{}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	wrm.On("GetAccessTokenFromAuthCode", authCodeRequest.authParameters, authCodeRequest.code, authCodeRequest.codeChallenge).Return(actualTokenResp, nil)
	_, err := authCodeRequest.Execute()
	if err != nil {
		t.Errorf("Error is supposed to be nil, instead it is %v", err)
	}
}
