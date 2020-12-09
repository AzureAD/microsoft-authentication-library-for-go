// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
	"github.com/stretchr/testify/mock"
)

type fakeManager struct {
	manager // embed the interface to prevent changes breaking it

	trcErr, ctrErr bool
}

func (f *fakeManager) Read(ctx context.Context, authParameters msalbase.AuthParametersInternal, webRequestManager requests.WebRequestManager) (msalbase.StorageTokenResponse, error) {
	if f.trcErr {
		return msalbase.StorageTokenResponse{}, errors.New("error")
	}

	at := new(msalbase.MockAccessToken)
	rt := new(msalbase.MockCredential)
	id := new(msalbase.MockCredential)
	at.On("GetSecret").Return("secret")
	at.On("GetExpiresOn").Return("0")
	at.On("GetScopes").Return("openid")
	rt.On("GetSecret").Return("secret")
	id.On("GetSecret").Return("secret")

	return msalbase.CreateStorageTokenResponse(at, rt, id, msalbase.Account{}), nil
}

func (f *fakeManager) Write(authParameters msalbase.AuthParametersInternal, tokenResponse msalbase.TokenResponse) (msalbase.Account, error) {
	if f.ctrErr {
		return msalbase.Account{}, errors.New("error")
	}

	return msalbase.Account{}, nil
}

func newTestApplication(fm *fakeManager, wrm *requests.MockWebRequestManager) *clientApplication {
	return &clientApplication{
		clientApplicationParameters: &clientApplicationParameters{
			commonParameters: &applicationCommonParameters{
				clientID:      "clientID",
				authorityInfo: testAuthorityInfo,
			},
		},
		webRequestManager: wrm,
		manager:           fm,
		cacheAccessor:     noopCacheAccessor{},
	}
}

// TODO(MSAL expert): These tests are bogus or missing important details.  Here are notes:
// TestAcquireTokenSilent: should be table driven and should change fakeManager or MockWebRequestManager
// to test various error states.  As is, tests a single positive state.
// TestExecuteTokenRequestWithoutCacheWrite/TestExecuteTokenRequestWithCacheWrite actually don't test
// those methods. They test that they error, which is a weird thing to test. Should test error and non error
// states using table driven tests.
func TestAcquireTokenSilent(t *testing.T) {
	silentParams := AcquireTokenSilentParameters{
		commonParameters: tokenCommonParams,
		account:          msalbase.Account{},
	}
	wrm := new(requests.MockWebRequestManager)
	fm := &fakeManager{}
	app := newTestApplication(fm, wrm)

	wrm.On(
		"GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration",
	).Return(tdr, nil)
	wrm.On(
		"GetAccessTokenFromRefreshToken",
		mock.AnythingOfType("msalbase.AuthParametersInternal"),
		"secret",
		url.Values{},
	).Return(msalbase.TokenResponse{}, nil)

	_, err := app.acquireTokenSilent(context.Background(), silentParams)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}

func TestExecuteTokenRequestWithoutCacheWrite(t *testing.T) {
	app := newTestApplication(nil, nil)

	testAuthParams := msalbase.CreateAuthParametersInternal("clientID", testAuthorityInfo)
	req := new(requests.MockTokenRequest)
	actualTokenResp := msalbase.TokenResponse{}
	req.On("Execute").Return(actualTokenResp, nil)
	_, err := app.executeTokenRequestWithoutCacheWrite(context.Background(), req, testAuthParams)
	if err != nil {
		t.Fatalf("Error should be nil, instead it is %v", err)
	}
	mockError := errors.New("This is a mock error")
	errorReq := new(requests.MockTokenRequest)
	errorReq.On("Execute").Return(msalbase.TokenResponse{}, mockError)
	_, err = app.executeTokenRequestWithoutCacheWrite(context.Background(), errorReq, testAuthParams)
	if err != mockError {
		t.Errorf("Actual error is %v, expected error is %v", err, mockError)
	}
}

func TestExecuteTokenRequestWithCacheWrite(t *testing.T) {
	app := newTestApplication(nil, nil)

	testAuthParams := msalbase.CreateAuthParametersInternal("clientID", testAuthorityInfo)
	mockError := errors.New("this is a mock error")
	errorReq := new(requests.MockTokenRequest)
	errorReq.On("Execute").Return(msalbase.TokenResponse{}, mockError)
	_, err := app.executeTokenRequestWithCacheWrite(context.Background(), errorReq, testAuthParams)
	if err != mockError {
		t.Errorf("Actual error is %v, expected error is %v", err, mockError)
	}
}
