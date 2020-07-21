// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

var testAuthorityEndpoints = msalbase.CreateAuthorityEndpoints("https://login.microsoftonline.com/v2.0/authorize",
	"https://login.microsoftonline.com/v2.0/token",
	"https://login.microsoftonline.com/v2.0",
	"https://login.microsoftonline.com")
var testAuthorityInfo, err = msalbase.CreateAuthorityInfoFromAuthorityUri("https://login.microsoftonline.com/v2.0/", true)
var testAuthParams = msalbase.CreateAuthParametersInternal("clientID", testAuthorityInfo)

var wrm = new(MockWebRequestManager)

var authCodeRequest = &AuthCodeRequest{
	webRequestManager: wrm,
	authParameters:    testAuthParams,
	Code:              "code",
	CodeChallenge:     "codeChallenge",
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
	wrm.On("GetAccessTokenFromAuthCode", authCodeRequest.authParameters, authCodeRequest.Code, authCodeRequest.CodeChallenge, "").Return(actualTokenResp, nil)
	_, err := authCodeRequest.Execute()
	if err != nil {
		t.Errorf("Error is supposed to be nil, instead it is %v", err)
	}
}
