// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
)

func TestAcquireTokenByClientCredential(t *testing.T) {
	testWrm := new(requests.MockWebRequestManager)
	testCacheManager := new(requests.MockCacheManager)
	cred, _ := msalbase.CreateClientCredentialFromSecret("client_secret")
	cca := &ConfidentialClientApplication{
		clientApplication: &clientApplication{
			clientApplicationParameters: clientAppParams,
			webRequestManager:           testWrm,
			cacheContext:                &CacheContext{testCacheManager},
		},
		clientCredential: cred,
	}
	testAuthParams := msalbase.CreateAuthParametersInternal("clientID", testAuthorityInfo)
	testAuthParams.Endpoints = testAuthorityEndpoints
	testAuthParams.Scopes = tokenCommonParams.scopes
	testAuthParams.AuthorizationType = msalbase.AuthorizationTypeClientCredentials
	testWrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	actualTokenResp := &msalbase.TokenResponse{}
	testWrm.On("GetAccessTokenWithClientSecret", testAuthParams, "client_secret").Return(actualTokenResp, nil)
	testCacheManager.On("CacheTokenResponse", testAuthParams, actualTokenResp).Return(testAcc, nil)
	clientCredParams := &AcquireTokenClientCredentialParameters{tokenCommonParams}
	_, err := cca.AcquireTokenByClientCredential(clientCredParams)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}
