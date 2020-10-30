// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
	"github.com/stretchr/testify/mock"
)

var tokenCommonParams = &acquireTokenCommonParameters{
	scopes: []string{"openid"},
}
var testAuthorityEndpoints = msalbase.CreateAuthorityEndpoints("https://login.microsoftonline.com/v2.0/authorize",
	"https://login.microsoftonline.com/v2.0/token",
	"https://login.microsoftonline.com/v2.0",
	"login.microsoftonline.com")
var testAuthorityInfo, _ = msalbase.CreateAuthorityInfoFromAuthorityURI("https://login.microsoftonline.com/v2.0/", true)

var tdr = &requests.TenantDiscoveryResponse{
	AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
	TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
	Issuer:                "https://login.microsoftonline.com/v2.0",
}

var testAcc = &msalbase.Account{}
var testPCA = &PublicClientApplication{
	clientApplication: testClientApplication,
}

func TestCreateAuthCodeURL(t *testing.T) {
	authCodeURLParams := CreateAuthorizationCodeURLParameters("clientID", "redirect", []string{"openid"})
	authCodeURLParams.CodeChallenge = "codeChallenge"
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	url, err := testPCA.CreateAuthCodeURL(authCodeURLParams)
	if err != nil {
		t.Errorf("Error should be nil, instead it is %v", err)
	}
	actualURL := "https://login.microsoftonline.com/v2.0/authorize?client_id=clientID&code_challenge=codeChallenge" +
		"&redirect_uri=redirect&response_type=code&scope=openid"
	if !reflect.DeepEqual(actualURL, url) {
		t.Errorf("URL should be %v, instead it is %v", actualURL, url)
	}
}

func TestAcquireTokenByAuthCode(t *testing.T) {
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	actualTokenResp := &msalbase.TokenResponse{}
	wrm.On("GetAccessTokenFromAuthCode", mock.AnythingOfType("*msalbase.AuthParametersInternal"), "", "", make(map[string]string)).Return(actualTokenResp, nil)
	cacheManager.On("CacheTokenResponse", mock.AnythingOfType("*msalbase.AuthParametersInternal"), actualTokenResp).Return(testAcc, nil)
	_, err := testPCA.AcquireTokenByAuthCode(context.Background(), []string{"openid"}, "", nil)
	if err != nil {
		t.Errorf("Error should be nil, instead it is %v", err)
	}
}

func TestAcquireTokenByUsernamePassword(t *testing.T) {
	managedUserRealm := &msalbase.UserRealm{
		AccountType: "Managed",
	}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	wrm.On("GetUserRealm", mock.AnythingOfType("*msalbase.AuthParametersInternal")).Return(managedUserRealm, nil)
	actualTokenResp := &msalbase.TokenResponse{}
	wrm.On("GetAccessTokenFromUsernamePassword", mock.AnythingOfType("*msalbase.AuthParametersInternal")).Return(actualTokenResp, nil)
	cacheManager.On("CacheTokenResponse", mock.AnythingOfType("*msalbase.AuthParametersInternal"), actualTokenResp).Return(testAcc, nil)
	_, err := testPCA.AcquireTokenByUsernamePassword(context.Background(), []string{"openid"}, "username", "password")
	if err != nil {
		t.Errorf("Error should be nil, instead it is %v", err)
	}
}

func TestGetAllAccounts(t *testing.T) {
	testAccOne := msalbase.NewAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")
	testAccTwo := msalbase.NewAccount("HID", "ENV", "REALM", "LID", msalbase.MSSTS, "USERNAME")
	expectedAccounts := []*msalbase.Account{testAccOne, testAccTwo}
	returnedAccounts := []*msalbase.Account{testAccOne, testAccTwo}
	cacheManager.On("GetAllAccounts").Return(expectedAccounts)
	actualAccounts := testPCA.Accounts()
	if !reflect.DeepEqual(actualAccounts, returnedAccounts) {
		t.Errorf("Actual accounts %v differ from expected accounts %v", actualAccounts, returnedAccounts)
	}
}

func TestAcquireTokenByDeviceCode(t *testing.T) {
	callback := func(dcr DeviceCodeResultProvider) {}
	cancelCtx, cancelFunc := context.WithTimeout(context.Background(), time.Duration(100)*time.Second)
	defer cancelFunc()
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	actualTokenResp := &msalbase.TokenResponse{}
	devCodeResp := &requests.DeviceCodeResponse{ExpiresIn: 10}
	devCodeResult := devCodeResp.ToDeviceCodeResult("clientID", tokenCommonParams.scopes)
	wrm.On("GetDeviceCodeResult", mock.AnythingOfType("*msalbase.AuthParametersInternal")).Return(devCodeResult, nil)
	wrm.On("GetAccessTokenFromDeviceCodeResult", mock.AnythingOfType("*msalbase.AuthParametersInternal"), devCodeResult).Return(actualTokenResp, nil)
	cacheManager.On("CacheTokenResponse", mock.AnythingOfType("*msalbase.AuthParametersInternal"), actualTokenResp).Return(testAcc, nil)
	_, err := testPCA.AcquireTokenByDeviceCode(cancelCtx, []string{"openid"}, callback, nil)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}
