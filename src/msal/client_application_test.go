// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"errors"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
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

func TestExecuteTokenRequestWithoutCacheWrite(t *testing.T) {
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
	mockError := errors.New("This is a mock error")
	errorReq := new(requests.MockTokenRequest)
	errorReq.On("Execute").Return(nil, mockError)
	_, err := testClientApplication.executeTokenRequestWithCacheWrite(errorReq, testAuthParams)
	if err != mockError {
		t.Errorf("Actual error is %v, expected error is %v", err, mockError)
	}
}
