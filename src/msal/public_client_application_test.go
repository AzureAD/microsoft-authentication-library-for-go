// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"reflect"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
)

var tokenCommonParams = &acquireTokenCommonParameters{
	scopes: []string{"openid"},
}
var testAuthorityEndpoints = msalbase.CreateAuthorityEndpoints("https://login.microsoftonline.com/v2.0/authorize",
	"https://login.microsoftonline.com/v2.0/token",
	"https://login.microsoftonline.com/v2.0",
	"login.microsoftonline.com")
var testAuthorityInfo, _ = msalbase.CreateAuthorityInfoFromAuthorityUri("https://login.microsoftonline.com/v2.0/", true)

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
	authCodeURLParams := CreateAuthorizationCodeURLParameters("clientID", "redirect", []string{"openid"}, "codeChallenge")
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
	testAuthParams := msalbase.CreateAuthParametersInternal("clientID", testAuthorityInfo)
	testAuthParams.Endpoints = testAuthorityEndpoints
	testAuthParams.AuthorizationType = msalbase.AuthorizationTypeAuthCode
	testAuthParams.Scopes = tokenCommonParams.scopes
	authCodeParams := &AcquireTokenAuthCodeParameters{
		commonParameters: tokenCommonParams,
	}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	actualTokenResp := &msalbase.TokenResponse{}
	wrm.On("GetAccessTokenFromAuthCode", testAuthParams, "", "", make(map[string]string)).Return(actualTokenResp, nil)
	cacheManager.On("CacheTokenResponse", testAuthParams, actualTokenResp).Return(testAcc, nil)
	_, err := testPCA.AcquireTokenByAuthCode(authCodeParams)
	if err != nil {
		t.Errorf("Error should be nil, instead it is %v", err)
	}
}

func TestAcquireTokenByUsernamePassword(t *testing.T) {
	testAuthParams := msalbase.CreateAuthParametersInternal("clientID", testAuthorityInfo)
	testAuthParams.Endpoints = testAuthorityEndpoints
	testAuthParams.AuthorizationType = msalbase.AuthorizationTypeUsernamePassword
	testAuthParams.Scopes = tokenCommonParams.scopes
	testAuthParams.Username = "username"
	testAuthParams.Password = "password"
	userPassParams := &AcquireTokenUsernamePasswordParameters{
		commonParameters: tokenCommonParams,
		username:         "username",
		password:         "password",
	}
	managedUserRealm := &msalbase.UserRealm{
		AccountType: "Managed",
	}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	wrm.On("GetUserRealm", testAuthParams).Return(managedUserRealm, nil)
	actualTokenResp := &msalbase.TokenResponse{}
	wrm.On("GetAccessTokenFromUsernamePassword", testAuthParams).Return(actualTokenResp, nil)
	_, err := testPCA.AcquireTokenByUsernamePassword(userPassParams)
	if err != nil {
		t.Errorf("Error should be nil, instead it is %v", err)
	}
}

func TestGetAllAccounts(t *testing.T) {
	testAccOne := msalbase.CreateAccount("hid", "env", "realm", "lid", msalbase.MSSTS, "username")
	testAccTwo := msalbase.CreateAccount("HID", "ENV", "REALM", "LID", msalbase.MSSTS, "USERNAME")
	expectedAccounts := []*msalbase.Account{testAccOne, testAccTwo}
	returnedAccounts := []AccountInterfacer{testAccOne, testAccTwo}
	cacheManager.On("GetAllAccounts").Return(expectedAccounts)
	actualAccounts := testPCA.GetAccounts()
	if !reflect.DeepEqual(actualAccounts, returnedAccounts) {
		t.Errorf("Actual accounts %v differ from expected accounts %v", actualAccounts, returnedAccounts)
	}
}

func TestAcquireTokenByDeviceCode(t *testing.T) {
	testAuthParams := msalbase.CreateAuthParametersInternal("clientID", testAuthorityInfo)
	testAuthParams.Endpoints = testAuthorityEndpoints
	testAuthParams.Scopes = tokenCommonParams.scopes
	testAuthParams.AuthorizationType = msalbase.AuthorizationTypeDeviceCode
	callback := func(dcr IDeviceCodeResult) {}
	devCodeParams := &AcquireTokenDeviceCodeParameters{
		commonParameters:   tokenCommonParams,
		deviceCodeCallback: callback,
	}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	actualTokenResp := &msalbase.TokenResponse{}
	devCodeResult := &msalbase.DeviceCodeResult{}
	wrm.On("GetDeviceCodeResult", testAuthParams).Return(devCodeResult, nil)
	wrm.On("GetAccessTokenFromDeviceCodeResult", testAuthParams, devCodeResult).Return(actualTokenResp, nil)
	cacheManager.On("CacheTokenResponse", testAuthParams, actualTokenResp).Return(testAcc, nil)
	_, err := testPCA.AcquireTokenByDeviceCode(devCodeParams)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}
