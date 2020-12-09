// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"context"
	"reflect"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
)

func TestCreateAcquireTokenAuthCodeParameters(t *testing.T) {
	expectedScopes := []string{"user.read"}
	params := createAcquireTokenAuthCodeParameters(expectedScopes)
	if params == nil {
		t.Error("Parameters cannot be nil.")
	}
	actualScopes := params.commonParameters.scopes
	if !reflect.DeepEqual(expectedScopes, actualScopes) {
		t.Errorf("Actual scopes %v differ from expected scopes %v", actualScopes, expectedScopes)
	}
}

func TestAugmentAuthenticationParametersForAuth(t *testing.T) {
	testScopes := []string{"user.read"}
	testAuthParams := msalbase.AuthParametersInternal{}
	testTokenCommonParams := acquireTokenCommonParameters{testScopes}
	testAuthCodeParams := acquireTokenAuthCodeParameters{
		commonParameters: testTokenCommonParams,
	}
	testAuthCodeParams.augmentAuthenticationParameters(&testAuthParams)
	actualScopes := testAuthParams.Scopes
	if !reflect.DeepEqual(testScopes, actualScopes) {
		t.Errorf("Actual scopes %v differ from expected scopes %v", actualScopes, testScopes)
	}
}

func TestCreateAcquireTokenCommonParameters(t *testing.T) {
	expectedScopes := []string{"user.read"}
	params := createAcquireTokenCommonParameters([]string{"User.Read"})
	actualScopes := params.scopes
	if !reflect.DeepEqual(expectedScopes, actualScopes) {
		t.Errorf("Actual scopes %v differ from expected scopes %v", actualScopes, expectedScopes)
	}
}

func TestAugmentAuthenticationParameters(t *testing.T) {
	testScopes := []string{"user.read"}
	testTokenParams := &acquireTokenCommonParameters{testScopes}
	testAuthParams := &msalbase.AuthParametersInternal{}
	testTokenParams.augmentAuthenticationParameters(testAuthParams)
	authScopes := testAuthParams.Scopes
	if !reflect.DeepEqual(testScopes, authScopes) {
		t.Errorf("Actual scopes %v differ from expected scopes %v", authScopes, testScopes)
	}
}

func TestAugmentAuthenticationParametersDeviceCode(t *testing.T) {
	testScopes := []string{"user.read"}
	testAuthParams := msalbase.AuthParametersInternal{}
	testTokenCommonParams := acquireTokenCommonParameters{testScopes}
	testDeviceCodeParams := acquireTokenDeviceCodeParameters{
		commonParameters: testTokenCommonParams,
	}
	testDeviceCodeParams.augmentAuthenticationParameters(&testAuthParams)
	actualScopes := testAuthParams.Scopes
	if !reflect.DeepEqual(testScopes, actualScopes) {
		t.Errorf("Actual scopes %v differ from expected scopes %v", actualScopes, testScopes)
	}
}

func TestAugmentAuthenticationParametersSilent(t *testing.T) {
	testScopes := []string{"user.read"}
	testAuthParams := msalbase.AuthParametersInternal{}
	testTokenCommonParams := acquireTokenCommonParameters{testScopes}
	homeAccountID := "hid"
	testAccount := msalbase.Account{
		HomeAccountID: homeAccountID,
	}
	testSilentParams := AcquireTokenSilentParameters{
		commonParameters: testTokenCommonParams,
		account:          testAccount,
	}
	testSilentParams.augmentAuthenticationParameters(&testAuthParams)
	actualScopes := testAuthParams.Scopes
	if !reflect.DeepEqual(testScopes, actualScopes) {
		t.Errorf("Actual scopes %v differ from expected scopes %v", actualScopes, testScopes)
	}
	actualHomeAccountID := testAuthParams.HomeaccountID
	if !reflect.DeepEqual(actualHomeAccountID, homeAccountID) {
		t.Errorf("Actual home account ID %s differs from expected home account ID %s", actualHomeAccountID, homeAccountID)
	}
}

func TestAugmentAuthenticationParametersForUsernamePass(t *testing.T) {
	testScopes := []string{"user.read"}
	testUsername := "testUser"
	testPassword := "testPass"
	testAuthParams := msalbase.AuthParametersInternal{}
	testTokenCommonParams := acquireTokenCommonParameters{testScopes}
	tokenUserPassParams := acquireTokenUsernamePasswordParameters{
		commonParameters: testTokenCommonParams,
		username:         testUsername,
		password:         testPassword,
	}
	tokenUserPassParams.augmentAuthenticationParameters(&testAuthParams)
	actualScopes := testAuthParams.Scopes
	if !reflect.DeepEqual(testScopes, actualScopes) {
		t.Errorf("Actual scopes %v differ from expected scopes %v", actualScopes, testScopes)
	}
	actualUsername := testAuthParams.Username
	if !reflect.DeepEqual(testUsername, actualUsername) {
		t.Errorf("Actual username %v differs from expected username %v", actualUsername, testUsername)
	}
	actualPassword := testAuthParams.Password
	if !reflect.DeepEqual(testPassword, actualPassword) {
		t.Errorf("Actual password %v differs from expected password %v", actualPassword, testPassword)
	}
}

var (
	testURLAuthorityInfo, _ = msalbase.CreateAuthorityInfoFromAuthorityURI("https://login.microsoftonline.com/v2.0/", true)
	testURLAuthParams       = msalbase.CreateAuthParametersInternal("clientID", testURLAuthorityInfo)
	urlWRM                  = new(requests.MockWebRequestManager)
	authCodeURLParams       = CreateAuthorizationCodeURLParameters("clientID", "redirect", []string{"openid", "user.read"})
)

func TestGetSeparatedScopes(t *testing.T) {
	expectedScopes := "openid user.read"
	actualSpaceSepScopes := authCodeURLParams.getSeparatedScopes()
	if !reflect.DeepEqual(actualSpaceSepScopes, expectedScopes) {
		t.Errorf("Actual separated scopes %v differs from expected space separated scopes %v", actualSpaceSepScopes, expectedScopes)
	}
}

func TestCreateURL(t *testing.T) {
	authCodeURLParams.CodeChallenge = "codeChallenge"
	tdr := requests.TenantDiscoveryResponse{
		AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
		TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
		Issuer:                "https://login.microsoftonline.com/v2.0",
	}
	urlWRM.On(
		"GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration",
	).Return(tdr, nil)
	url, err := authCodeURLParams.createURL(context.Background(), urlWRM, testURLAuthParams)
	if err != nil {
		t.Fatalf("Error is supposed to be nil, instead it is %v", err)
	}
	actualURL := "https://login.microsoftonline.com/v2.0/authorize?client_id=clientID&code_challenge=codeChallenge" +
		"&redirect_uri=redirect&response_type=code&scope=openid+user.read"
	if url != actualURL {
		t.Errorf("Actual URL %v differs from expected URL %v", actualURL, url)
	}
}
