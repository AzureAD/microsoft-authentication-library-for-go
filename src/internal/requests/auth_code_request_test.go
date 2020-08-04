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

func TestAuthCodeReqExecutePublic(t *testing.T) {
	var wrm = new(MockWebRequestManager)
	var authCodeRequest = &AuthCodeRequest{
		webRequestManager: wrm,
		authParameters:    testAuthParams,
		Code:              "code",
		CodeChallenge:     "codeChallenge",
	}
	tdr := &TenantDiscoveryResponse{
		AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
		TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
		Issuer:                "https://login.microsoftonline.com/v2.0",
	}
	actualTokenResp := &msalbase.TokenResponse{}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	wrm.On("GetAccessTokenFromAuthCode", authCodeRequest.authParameters, authCodeRequest.Code,
		authCodeRequest.CodeChallenge, make(map[string]string)).Return(actualTokenResp, nil)
	_, err := authCodeRequest.Execute()
	if err != nil {
		t.Errorf("Error is supposed to be nil, instead it is %v", err)
	}
}

func TestAuthCodeReqExecuteAssertion(t *testing.T) {
	var wrm = new(MockWebRequestManager)
	var authCodeRequest = &AuthCodeRequest{
		webRequestManager: wrm,
		authParameters:    testAuthParams,
		Code:              "code",
		CodeChallenge:     "codeChallenge",
		RequestType:       AuthCodeClientAssertion,
		ClientAssertion:   msalbase.CreateClientAssertionFromJWT("hello"),
	}
	tdr := &TenantDiscoveryResponse{
		AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
		TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
		Issuer:                "https://login.microsoftonline.com/v2.0",
	}
	actualTokenResp := &msalbase.TokenResponse{}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	wrm.On("GetAccessTokenFromAuthCode", authCodeRequest.authParameters, authCodeRequest.Code,
		authCodeRequest.CodeChallenge, map[string]string{
			"client_assertion":      "hello",
			"client_assertion_type": msalbase.ClientAssertionGrant,
		}).Return(actualTokenResp, nil)
	_, err := authCodeRequest.Execute()
	if err != nil {
		t.Errorf("Error is supposed to be nil, instead it is %v", err)
	}
}

func TestAuthCodeReqExecuteSecret(t *testing.T) {
	var wrm = new(MockWebRequestManager)
	var authCodeRequest = &AuthCodeRequest{
		webRequestManager: wrm,
		authParameters:    testAuthParams,
		Code:              "code",
		CodeChallenge:     "codeChallenge",
		RequestType:       AuthCodeClientSecret,
		ClientSecret:      "secret",
	}
	tdr := &TenantDiscoveryResponse{
		AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
		TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
		Issuer:                "https://login.microsoftonline.com/v2.0",
	}
	actualTokenResp := &msalbase.TokenResponse{}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	wrm.On("GetAccessTokenFromAuthCode", authCodeRequest.authParameters, authCodeRequest.Code,
		authCodeRequest.CodeChallenge, map[string]string{
			"client_secret": "secret",
		}).Return(actualTokenResp, nil)
	_, err := authCodeRequest.Execute()
	if err != nil {
		t.Errorf("Error is supposed to be nil, instead it is %v", err)
	}
}
