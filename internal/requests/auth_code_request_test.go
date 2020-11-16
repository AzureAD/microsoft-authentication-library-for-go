// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

func createTestAuthorityInfo() msalbase.AuthorityInfo {
	info, err := msalbase.CreateAuthorityInfoFromAuthorityURI("https://login.microsoftonline.com/v2.0/", true)
	if err != nil {
		panic(err)
	}
	return info
}

func createTDR() TenantDiscoveryResponse {
	return TenantDiscoveryResponse{
		AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
		TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
		Issuer:                "https://login.microsoftonline.com/v2.0",
	}
}

func createACRTestParams() msalbase.AuthParametersInternal {
	tdr := createTDR()
	params := msalbase.CreateAuthParametersInternal("clientID", createTestAuthorityInfo())
	// TODO(msal expert): This is the only change here that is an actual change of the test. This is
	// also changed in other mock tests. Found that calls to methods like AuthCodeRequest.Execute()
	// would set these Endpoints. But for some reason, none of the mocks expected it.
	// I'm not sure why this worked (another reason for not using mocks), but I am
	// pretty sure the mock call to GetAccessTokenFromAuthCode should have seen these.
	// So I fixed it here, but someone should verify I'm not doing something bad.
	params.Endpoints = msalbase.CreateAuthorityEndpoints(
		tdr.AuthorizationEndpoint,
		tdr.TokenEndpoint,
		tdr.Issuer,
		"login.microsoftonline.com",
	)
	return params
}

func TestAuthCodeReqExecutePublic(t *testing.T) {
	var wrm = new(MockWebRequestManager)
	var authCodeRequest = &AuthCodeRequest{
		webRequestManager: wrm,
		authParameters:    createACRTestParams(),
		Code:              "code",
		CodeChallenge:     "codeChallenge",
	}

	actualTokenResp := msalbase.TokenResponse{}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(createTDR(), nil)
	wrm.On("GetAccessTokenFromAuthCode", authCodeRequest.authParameters, authCodeRequest.Code,
		authCodeRequest.CodeChallenge, map[string]string{}).Return(actualTokenResp, nil)
	_, err := authCodeRequest.Execute()
	if err != nil {
		t.Errorf("TestAuthCodeReqExecutePublic: got err == %s, want err == nil", err)
	}
}

func TestAuthCodeReqExecuteAssertion(t *testing.T) {
	var wrm = new(MockWebRequestManager)
	cred, err := msalbase.CreateClientCredentialFromAssertion("hello")
	if err != nil {
		panic(err)
	}

	var authCodeRequest = &AuthCodeRequest{
		webRequestManager: wrm,
		authParameters:    createACRTestParams(),
		Code:              "code",
		CodeChallenge:     "codeChallenge",
		RequestType:       AuthCodeConfidential,
		ClientCredential:  cred,
	}

	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration",
	).Return(createTDR(), nil)

	wrm.On(
		"GetAccessTokenFromAuthCode",
		authCodeRequest.authParameters,
		authCodeRequest.Code,
		authCodeRequest.CodeChallenge,
		map[string]string{
			"client_assertion":      "hello",
			"client_assertion_type": msalbase.ClientAssertionGrant,
		},
	).Return(msalbase.TokenResponse{}, nil)

	_, err = authCodeRequest.Execute()
	if err != nil {
		t.Errorf("Error is supposed to be nil, instead it is %v", err)
	}
}

func TestAuthCodeReqExecuteSecret(t *testing.T) {
	var wrm = new(MockWebRequestManager)
	cred, _ := msalbase.CreateClientCredentialFromSecret("secret")
	var authCodeRequest = &AuthCodeRequest{
		webRequestManager: wrm,
		authParameters:    createACRTestParams(),
		Code:              "code",
		CodeChallenge:     "codeChallenge",
		RequestType:       AuthCodeConfidential,
		ClientCredential:  cred,
	}

	actualTokenResp := msalbase.TokenResponse{}
	wrm.On(
		"GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration",
	).Return(createTDR(), nil)
	wrm.On("GetAccessTokenFromAuthCode", authCodeRequest.authParameters, authCodeRequest.Code,
		authCodeRequest.CodeChallenge, map[string]string{
			"client_secret": "secret",
		}).Return(actualTokenResp, nil)
	_, err := authCodeRequest.Execute()
	if err != nil {
		t.Errorf("Error is supposed to be nil, instead it is %v", err)
	}
}
