// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

func TestClientCredentialReqExecuteWithAssertion(t *testing.T) {
	testAuthorityInfo, _ := msalbase.CreateAuthorityInfoFromAuthorityURI("https://login.microsoftonline.com/v2.0/", true)
	testAuthParams := msalbase.CreateAuthParametersInternal("clientID", testAuthorityInfo)
	wrm := new(MockWebRequestManager)
	cred, _ := msalbase.CreateClientCredentialFromAssertion("hello")
	req := &ClientCredentialRequest{
		webRequestManager: wrm,
		authParameters:    testAuthParams,
		clientCredential:  cred,
	}
	tdr := &TenantDiscoveryResponse{
		AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
		TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
		Issuer:                "https://login.microsoftonline.com/v2.0",
	}
	actualTokenResp := &msalbase.TokenResponse{}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	wrm.On("GetAccessTokenWithAssertion", testAuthParams, "hello").Return(actualTokenResp, nil)
	_, err := req.Execute()
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}

func TestClientCredentialReqExecuteWithSecret(t *testing.T) {
	testAuthorityInfo, _ := msalbase.CreateAuthorityInfoFromAuthorityURI("https://login.microsoftonline.com/v2.0/", true)
	testAuthParams := msalbase.CreateAuthParametersInternal("clientID", testAuthorityInfo)
	wrm := new(MockWebRequestManager)
	cred, _ := msalbase.CreateClientCredentialFromSecret("hello")
	req := &ClientCredentialRequest{
		webRequestManager: wrm,
		authParameters:    testAuthParams,
		clientCredential:  cred,
	}
	tdr := &TenantDiscoveryResponse{
		AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
		TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
		Issuer:                "https://login.microsoftonline.com/v2.0",
	}
	actualTokenResp := &msalbase.TokenResponse{}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	wrm.On("GetAccessTokenWithClientSecret", testAuthParams, "hello").Return(actualTokenResp, nil)
	_, err := req.Execute()
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}
