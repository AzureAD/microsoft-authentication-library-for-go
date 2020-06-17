// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package msalgo

import (
	"reflect"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/tokencache"
)

var tokenCommonParams = &acquireTokenCommonParameters{
	scopes: []string{"openid"},
}
var testAuthorityEndpoints = msalbase.CreateAuthorityEndpoints("https://login.microsoftonline.com/v2.0/authorize",
	"https://login.microsoftonline.com/v2.0/token",
	"https://login.microsoftonline.com/v2.0",
	"login.microsoftonline.com")
var testAuthorityInfo, err = msalbase.CreateAuthorityInfoFromAuthorityUri("https://login.microsoftonline.com/v2.0/", true)
var testAuthParams = msalbase.CreateAuthParametersInternal("clientID", testAuthorityInfo)
var appCommonParams = &applicationCommonParameters{
	clientID:      "clientID",
	authorityInfo: testAuthorityInfo,
}
var pcaParams = &PublicClientApplicationParameters{
	commonParameters: appCommonParams,
}
var wrm = new(requests.MockWebRequestManager)
var testPCA = &PublicClientApplication{
	pcaParameters:     pcaParams,
	webRequestManager: wrm,
	cacheManager:      new(tokencache.MockCacheManager),
}

func TestAcquireAuthCodeURL(t *testing.T) {
	authCodeParams := &AcquireTokenAuthCodeParameters{
		commonParameters:    tokenCommonParams,
		codeChallenge:       "codeChallenge",
		codeChallengeMethod: "plain",
		redirectURI:         "redirect",
	}
	tdr := &requests.TenantDiscoveryResponse{
		AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
		TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
		Issuer:                "https://login.microsoftonline.com/v2.0",
	}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	url, err := testPCA.AcquireAuthCodeURL(authCodeParams)
	if err != nil {
		t.Errorf("Error should be nil, instead it is %v", err)
	}
	actualURL := "https://login.microsoftonline.com/v2.0/authorize?client_id=clientID&code_challenge=codeChallenge" +
		"&code_challenge_method=plain&redirect_uri=redirect&response_type=code&scope=openid"
	if !reflect.DeepEqual(actualURL, url) {
		t.Errorf("URL should be %v, instead it is %v", actualURL, url)
	}
}

func TestAcquireTokenByAuthCode(t *testing.T) {
	testAuthParams.SetAuthorityEndpoints(testAuthorityEndpoints)
	testAuthParams.SetAuthorizationType(msalbase.AuthorizationTypeAuthCode)
	testAuthParams.SetScopes(tokenCommonParams.scopes)
	authCodeParams := &AcquireTokenAuthCodeParameters{
		commonParameters: tokenCommonParams,
	}
	tdr := &requests.TenantDiscoveryResponse{
		AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
		TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
		Issuer:                "https://login.microsoftonline.com/v2.0",
	}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	actualTokenResp := &msalbase.TokenResponse{}
	wrm.On("GetAccessTokenFromAuthCode", testAuthParams, "", "").Return(actualTokenResp, nil)
	_, err := testPCA.AcquireTokenByAuthCode(authCodeParams)
	if err != nil {
		t.Errorf("Error should be nil, instead it is %v", err)
	}
}
