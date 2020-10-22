// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"errors"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
	"github.com/stretchr/testify/mock"
)

var (
	appCommonParams = &applicationCommonParameters{
		clientID:      "clientID",
		authorityInfo: testAuthorityInfo,
	}
	clientAppParams = &clientApplicationParameters{
		commonParameters: appCommonParams,
	}
	wrm                   = new(requests.MockWebRequestManager)
	cacheManager          = new(requests.MockCacheManager)
	testClientApplication = &clientApplication{
		clientApplicationParameters: clientAppParams,
		webRequestManager:           wrm,
		cacheContext:                &CacheContext{cacheManager},
	}
)

func TestAcquireTokenSilent(t *testing.T) {
	account := &msalbase.Account{}
	silentParams := &AcquireTokenSilentParameters{
		commonParameters: tokenCommonParams,
		account:          account,
	}
	at := new(msalbase.MockAccessToken)
	rt := new(msalbase.MockCredential)
	id := new(msalbase.MockCredential)
	storageToken := msalbase.CreateStorageTokenResponse(at, rt, id, account)
	cacheManager.On("TryReadCache", mock.AnythingOfType("*msalbase.AuthParametersInternal"), wrm).Return(storageToken, nil)
	tokenResp := &msalbase.TokenResponse{}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	wrm.On("GetAccessTokenFromRefreshToken", mock.AnythingOfType("*msalbase.AuthParametersInternal"), "secret", make(map[string]string)).Return(tokenResp, nil)
	cacheManager.On("CacheTokenResponse", mock.AnythingOfType("*msalbase.AuthParametersInternal"), tokenResp).Return(testAcc, nil)
	at.On("GetSecret").Return("secret")
	at.On("GetExpiresOn").Return("0")
	at.On("GetScopes").Return("openid")
	rt.On("GetSecret").Return("secret")
	id.On("GetSecret").Return("secret")
	_, err := testClientApplication.acquireTokenSilent(silentParams)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}

func TestExecuteTokenRequestWithoutCacheWrite(t *testing.T) {
	testAuthParams := msalbase.CreateAuthParametersInternal("clientID", testAuthorityInfo)
	req := new(requests.MockTokenRequest)
	actualTokenResp := &msalbase.TokenResponse{}
	req.On("Execute").Return(actualTokenResp, nil)
	_, err := testClientApplication.executeTokenRequestWithoutCacheWrite(req, testAuthParams)
	if err != nil {
		t.Errorf("Error should be nil, instead it is %v", err)
	}
	mockError := errors.New("This is a mock error")
	errorReq := new(requests.MockTokenRequest)
	errorReq.On("Execute").Return(nil, mockError)
	_, err = testClientApplication.executeTokenRequestWithoutCacheWrite(errorReq, testAuthParams)
	if err != mockError {
		t.Errorf("Actual error is %v, expected error is %v", err, mockError)
	}
}

func TestExecuteTokenRequestWithCacheWrite(t *testing.T) {
	testAuthParams := msalbase.CreateAuthParametersInternal("clientID", testAuthorityInfo)
	mockError := errors.New("This is a mock error")
	errorReq := new(requests.MockTokenRequest)
	errorReq.On("Execute").Return(nil, mockError)
	_, err := testClientApplication.executeTokenRequestWithCacheWrite(errorReq, testAuthParams)
	if err != mockError {
		t.Errorf("Actual error is %v, expected error is %v", err, mockError)
	}
}
