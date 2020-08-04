// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"errors"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/tokencache"
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
	authParams := &msalbase.AuthParametersInternal{
		AuthorityInfo:     testAuthorityInfo,
		ClientID:          "clientID",
		Scopes:            []string{"openid"},
		AuthorizationType: msalbase.AuthorizationTypeRefreshTokenExchange,
	}
	at := tokencache.CreateAccessTokenCacheItem("hid", "env", "realm", "clientID", 0, 0, 0, "openid", "secret")
	rt := tokencache.CreateRefreshTokenCacheItem("hid", "env", "clientID", "secret", "")
	id := tokencache.CreateIDTokenCacheItem("hid", "env", "realm", "clientID", "secret")
	storageToken := msalbase.CreateStorageTokenResponse(at, rt, id, account)
	cacheManager.On("TryReadCache", authParams, wrm).Return(storageToken, nil)
	wrmauthParams := &msalbase.AuthParametersInternal{
		AuthorityInfo:     testAuthorityInfo,
		ClientID:          "clientID",
		Scopes:            []string{"openid"},
		AuthorizationType: msalbase.AuthorizationTypeRefreshTokenExchange,
		Endpoints:         testAuthorityEndpoints,
	}
	tokenResp := &msalbase.TokenResponse{}
	wrm.On("GetAccessTokenFromRefreshToken", wrmauthParams, "secret").Return(tokenResp, nil)
	cacheManager.On("CacheTokenResponse", wrmauthParams, tokenResp).Return(testAcc, nil)
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
