// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

func TestClientCredentialReqExecuteWithAssertion(t *testing.T) {
	testAuthorityInfo, err := msalbase.CreateAuthorityInfoFromAuthorityURI("https://login.microsoftonline.com/v2.0/", true)
	if err != nil {
		panic(err)
	}
	testAuthParams := msalbase.CreateAuthParametersInternal("clientID", testAuthorityInfo)
	wrm := new(MockWebRequestManager)
	cred, err := msalbase.CreateClientCredentialFromAssertion("hello")
	if err != nil {
		panic(err)
	}
	req := &ClientCredentialRequest{
		webRequestManager: wrm,
		authParameters:    testAuthParams,
		clientCredential:  cred,
	}
	tdr := TenantDiscoveryResponse{
		AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
		TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
		Issuer:                "https://login.microsoftonline.com/v2.0",
	}
	testAuthParams.Endpoints = msalbase.CreateAuthorityEndpoints(
		tdr.AuthorizationEndpoint,
		tdr.TokenEndpoint,
		tdr.Issuer,
		"login.microsoftonline.com",
	)

	wrm.On(
		"GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration",
	).Return(tdr, nil)
	wrm.On(
		"GetAccessTokenWithAssertion",
		testAuthParams,
		"hello",
	).Return(msalbase.TokenResponse{}, nil)

	_, err = req.Execute()
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}

func TestClientCredentialReqExecuteWithSecret(t *testing.T) {
	authParams := createACRTestParams()
	wrm := new(MockWebRequestManager)
	cred, err := msalbase.CreateClientCredentialFromSecret("hello")
	if err != nil {
		panic(err)
	}
	req := &ClientCredentialRequest{
		webRequestManager: wrm,
		authParameters:    authParams,
		clientCredential:  cred,
	}
	tdr := TenantDiscoveryResponse{
		AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
		TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
		Issuer:                "https://login.microsoftonline.com/v2.0",
	}

	wrm.On(
		"GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration",
	).Return(tdr, nil)
	wrm.On(
		"GetAccessTokenWithClientSecret",
		authParams,
		"hello",
	).Return(msalbase.TokenResponse{}, nil)

	_, err = req.Execute()
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}
