// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package msalgo

import (
	"fmt"
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
	authResult, err := testPCA.AcquireTokenByAuthCode(authCodeParams)
	fmt.Println(fmt.Sprintf("%v", authResult))
	if err != nil {
		t.Errorf("Error should be nil, instead it is %v", err)
	}
}
