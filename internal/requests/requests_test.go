// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

const (
	responseData = `{"tenant_discovery_response": "hello", "metadata":
				 [{"preferred_network": "hello", "preferred_cache": "hello", "tenant_discovery_endpoint": "hello"}]}`
	tdrText = `{"authorization_endpoint": "auth", "token_endpoint": "token", "issuer": "iss"}`
)

func createTDR() TenantDiscoveryResponse {
	return TenantDiscoveryResponse{
		AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
		TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
		Issuer:                "https://login.microsoftonline.com/v2.0",
	}
}

func createACRTestParams() msalbase.AuthParametersInternal {
	tdr := createTDR()
	params := msalbase.CreateAuthParametersInternal("clientID", createTestAuthorityInfo())
	// TODO(msal expert): This is the only change here that is an actual change of the test. This is
	// also changed in other mock tests. Found that calls to methods like AuthCodeRequest.Execute()
	// would set these Endpoints. But for some reason, none of the mocks expected it.
	// I'm not sure why this worked (another reason for not using mocks), but I am
	// pretty sure the mock call to GetAccessTokenFromAuthCode should have seen these.
	// So I fixed it here, but someone should verify I'm not doing something bad.
	params.Endpoints = msalbase.CreateAuthorityEndpoints(
		tdr.AuthorizationEndpoint,
		tdr.TokenEndpoint,
		tdr.Issuer,
		"login.microsoftonline.com",
	)
	return params
}

var expDevCodeResp = &DeviceCodeResponse{
	UserCode:        "user",
	DeviceCode:      "dev",
	VerificationURL: "url",
	ExpiresIn:       10,
	Interval:        5,
	Message:         "message",
}

func createFakeResp(code int, body string) *http.Response {
	return &http.Response{
		Body:       ioutil.NopCloser(strings.NewReader(body)),
		StatusCode: code,
	}
}

func TestGetMetadataEntry(t *testing.T) {
	authInfo := msalbase.AuthorityInfo{
		Host: "login.microsoft.com",
	}
	mockWRM := new(MockWebRequestManager)
	metEntry := InstanceDiscoveryMetadata{
		Aliases: []string{"login.microsoft.com"},
	}
	instanceDisc := CreateAadInstanceDiscovery(mockWRM)
	instanceResp := InstanceDiscoveryResponse{
		TenantDiscoveryEndpoint: "",
		Metadata:                []InstanceDiscoveryMetadata{metEntry},
	}
	mockWRM.On("GetAadinstanceDiscoveryResponse", authInfo).Return(instanceResp, nil)
	actualMet, err := instanceDisc.GetMetadataEntry(context.Background(), authInfo)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualMet, metEntry) {
		t.Errorf("Actual metadata entry %+v differs from expected metadata entry %+v", actualMet, metEntry)
	}
}

func createTestAuthorityInfo() msalbase.AuthorityInfo {
	info, err := msalbase.CreateAuthorityInfoFromAuthorityURI("https://login.microsoftonline.com/v2.0/", true)
	if err != nil {
		panic(err)
	}
	return info
}

func TestAuthCodeReqExecutePublic(t *testing.T) {
	var wrm = new(MockWebRequestManager)
	var authCodeRequest = &AuthCodeRequest{
		webRequestManager: wrm,
		authParameters:    createACRTestParams(),
		Code:              "code",
		CodeChallenge:     "codeChallenge",
	}

	actualTokenResp := msalbase.TokenResponse{}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(createTDR(), nil)
	wrm.On("GetAccessTokenFromAuthCode", authCodeRequest.authParameters, authCodeRequest.Code,
		authCodeRequest.CodeChallenge, url.Values{}).Return(actualTokenResp, nil)
	_, err := authCodeRequest.Execute(context.Background())
	if err != nil {
		t.Errorf("TestAuthCodeReqExecutePublic: got err == %s, want err == nil", err)
	}
}

func TestAuthCodeReqExecuteAssertion(t *testing.T) {
	var wrm = new(MockWebRequestManager)
	cred, err := msalbase.CreateClientCredentialFromAssertion("hello")
	if err != nil {
		panic(err)
	}

	var authCodeRequest = &AuthCodeRequest{
		webRequestManager: wrm,
		authParameters:    createACRTestParams(),
		Code:              "code",
		CodeChallenge:     "codeChallenge",
		RequestType:       AuthCodeConfidential,
		ClientCredential:  cred,
	}

	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration",
	).Return(createTDR(), nil)

	queryParams := url.Values{}
	queryParams.Set("client_assertion", "hello")
	queryParams.Set("client_assertion_type", msalbase.ClientAssertionGrant)
	wrm.On(
		"GetAccessTokenFromAuthCode",
		authCodeRequest.authParameters,
		authCodeRequest.Code,
		authCodeRequest.CodeChallenge,
		queryParams,
	).Return(msalbase.TokenResponse{}, nil)

	_, err = authCodeRequest.Execute(context.Background())
	if err != nil {
		t.Errorf("Error is supposed to be nil, instead it is %v", err)
	}
}

func TestAuthCodeReqExecuteSecret(t *testing.T) {
	var wrm = new(MockWebRequestManager)
	cred, _ := msalbase.CreateClientCredentialFromSecret("secret")
	var authCodeRequest = &AuthCodeRequest{
		webRequestManager: wrm,
		authParameters:    createACRTestParams(),
		Code:              "code",
		CodeChallenge:     "codeChallenge",
		RequestType:       AuthCodeConfidential,
		ClientCredential:  cred,
	}

	actualTokenResp := msalbase.TokenResponse{}
	wrm.On(
		"GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration",
	).Return(createTDR(), nil)
	queryParams := url.Values{}
	queryParams.Set("client_secret", "secret")
	wrm.On("GetAccessTokenFromAuthCode", authCodeRequest.authParameters, authCodeRequest.Code,
		authCodeRequest.CodeChallenge, queryParams).Return(actualTokenResp, nil)
	_, err := authCodeRequest.Execute(context.Background())
	if err != nil {
		t.Errorf("Error is supposed to be nil, instead it is %v", err)
	}
}

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

	_, err = req.Execute(context.Background())
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

	_, err = req.Execute(context.Background())
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}

func TestCreateDeviceCodeResponse(t *testing.T) {
	dcrText := `{"user_code": "user", "device_code": "dev", "verification_url": "url",
				"expires_in": 10, "interval": 5, "message": "message"}`
	actualDCR, err := CreateDeviceCodeResponse(createFakeResp(http.StatusOK, dcrText))
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(expDevCodeResp.UserCode, actualDCR.UserCode) &&
		!reflect.DeepEqual(expDevCodeResp.DeviceCode, actualDCR.DeviceCode) &&
		!reflect.DeepEqual(expDevCodeResp.VerificationURL, actualDCR.VerificationURL) &&
		!reflect.DeepEqual(expDevCodeResp.ExpiresIn, actualDCR.ExpiresIn) &&
		!reflect.DeepEqual(expDevCodeResp.Interval, actualDCR.Interval) &&
		!reflect.DeepEqual(expDevCodeResp.Message, actualDCR.Message) {
		t.Errorf("Actual device code response %+v differs from expected device code response %+v", actualDCR, expDevCodeResp)
	}
}

func TestCreateInstanceDiscoveryResponse(t *testing.T) {
	expInstDisc := &InstanceDiscoveryResponse{
		TenantDiscoveryEndpoint: "hello",
		Metadata: []InstanceDiscoveryMetadata{
			{
				PreferredCache:          "hello",
				PreferredNetwork:        "hello",
				TenantDiscoveryEndpoint: "hello",
			},
		},
	}
	actualInstDisc, err := CreateInstanceDiscoveryResponse(createFakeResp(http.StatusOK, responseData))
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualInstDisc.TenantDiscoveryEndpoint, expInstDisc.TenantDiscoveryEndpoint) &&
		!reflect.DeepEqual(actualInstDisc.Metadata, expInstDisc.Metadata) {
		t.Errorf("Actual instance discovery response %+v differs from expected instance discovery response %+v",
			actualInstDisc, expInstDisc)
	}
}

func TestCreateTenantDiscoveryResponse(t *testing.T) {
	expectedTDR := &TenantDiscoveryResponse{
		AuthorizationEndpoint: "auth",
		TokenEndpoint:         "token",
		Issuer:                "iss",
	}
	actualTDR, err := CreateTenantDiscoveryResponse(createFakeResp(http.StatusOK, tdrText))
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(expectedTDR.AuthorizationEndpoint, actualTDR.AuthorizationEndpoint) &&
		!reflect.DeepEqual(expectedTDR.TokenEndpoint, actualTDR.TokenEndpoint) &&
		!reflect.DeepEqual(expectedTDR.Issuer, actualTDR.Issuer) {
		t.Errorf("Actual tenant discovery response %+v differs from expected tenant discovery response %+v", actualTDR, expectedTDR)
	}
}

// NOTE: I kept these init() and var down here because they go directly with
// the following tests. This of course should be fixed.

// TODO(jdoak): Replace these tests with subtests to eliminate these globals
// or table driven.

var (
	testUPAuthorityInfo msalbase.AuthorityInfo
	uprTestAuthParams   msalbase.AuthParametersInternal

	upWRM               = new(MockWebRequestManager)
	usernamePassRequest *UsernamePasswordRequest

	managedUserRealm = msalbase.UserRealm{
		AccountType: "Managed",
	}
	errorUserRealm = msalbase.UserRealm{
		AccountType: "",
	}
)

func init() {
	var err error
	testUPAuthorityInfo, err = msalbase.CreateAuthorityInfoFromAuthorityURI("https://login.microsoftonline.com/v2.0/", true)
	if err != nil {
		panic(err)
	}

	uprTestAuthParams = msalbase.CreateAuthParametersInternal("clientID", createTestAuthorityInfo())
	uprTestAuthParams.Endpoints = msalbase.CreateAuthorityEndpoints(
		"https://login.microsoftonline.com/v2.0/authorize",
		"https://login.microsoftonline.com/v2.0/token",
		"https://login.microsoftonline.com/v2.0",
		"login.microsoftonline.com",
	)

	usernamePassRequest = &UsernamePasswordRequest{
		authParameters: uprTestAuthParams,
	}
}

// TODO(msal expert): This test SEEMS borked. .Execute()
// calls wsTrustResp.GetSAMLAssertion(). Because mexDoc.UsernamePasswordEndpoint is
// set to wsEndpoint with wstrust.Trust2005, Response.GetSAMLAssertion() will error
// with non-supported. This is what should have been happening as far as I can tell.
// So this test should have never worked.  Trust13 is supported, but switching to it
// just causes it to give an EOL error, probably because it has to do some parsing.
// I don't know what that needs to be and would defer to experts to let me know.
/*
func TestUsernamePassExecuteWithFederated(t *testing.T) {
	upWRM = new(MockWebRequestManager)
	usernamePassRequest.webRequestManager = upWRM
	upWRM.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	upWRM.On("GetUserRealm", usernamePassRequest.authParameters).Return(federatedUserRealm, nil)
	wsEndpoint := wstrust.Endpoint{EndpointVersion: wstrust.Trust2005, URL: "upEndpoint"}
	mexDoc := wstrust.MexDocument{
		UsernamePasswordEndpoint: wsEndpoint,
	}
	upWRM.On("GetMex", "fedMetaURL").Return(mexDoc, nil)
	wsTrustResp := wstrust.Response{}
	upWRM.On("GetWsTrustResponse", uprTestAuthParams, "", wsEndpoint).Return(wsTrustResp, nil)
	_, err := usernamePassRequest.Execute()
	if err != nil {
		t.Errorf("Error should be nil, but is %v", err)
	}
}
*/

func TestUsernamePassExecuteWithManaged(t *testing.T) {
	upWRM = new(MockWebRequestManager)
	usernamePassRequest.webRequestManager = upWRM
	upWRM.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(createTDR(), nil)
	upWRM.On("GetUserRealm", usernamePassRequest.authParameters).Return(managedUserRealm, nil)
	actualTokenResp := msalbase.TokenResponse{}
	upWRM.On("GetAccessTokenFromUsernamePassword", usernamePassRequest.authParameters).Return(actualTokenResp, nil)
	_, err := usernamePassRequest.Execute(context.Background())
	if err != nil {
		t.Errorf("Error is supposed to be nil, instead it is %v", err)
	}
}

func TestUsernamePassExecuteWithAcctError(t *testing.T) {
	newUpWRM := new(MockWebRequestManager)
	usernamePassRequest.webRequestManager = newUpWRM
	newUpWRM.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(createTDR(), nil)
	newUpWRM.On("GetUserRealm", usernamePassRequest.authParameters).Return(errorUserRealm, nil)
	_, acctError := usernamePassRequest.Execute(context.Background())
	expectedErrorMessage := "unknown account type"
	if acctError == nil {
		t.Errorf("Error is nil, should be %v", errors.New(expectedErrorMessage))
	}
	if !reflect.DeepEqual(acctError.Error(), expectedErrorMessage) {
		t.Errorf("Actual error message %v differs from expected error message %v", acctError.Error(), expectedErrorMessage)
	}
}
