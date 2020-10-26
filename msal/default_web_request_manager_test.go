// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/wstrust"
)

var testHeaders = map[string]string{
	"x-client-SKU":             "MSAL.Go",
	"x-client-OS":              runtime.GOOS,
	"client-request-id":        "",
	"return-client-request-id": "false",
}
var testHeadersWURLUTF8 = map[string]string{
	"x-client-SKU":             "MSAL.Go",
	"x-client-OS":              runtime.GOOS,
	"client-request-id":        "",
	"return-client-request-id": "false",
	"Content-Type":             "application/x-www-form-urlencoded; charset=utf-8",
}

func TestAddContentTypeHeader(t *testing.T) {
	testHeaders := make(map[string]string)
	addContentTypeHeader(testHeaders, soapXMLUtf8)
	expectedContentHeader := "application/soap+xml; charset=utf-8"
	if !reflect.DeepEqual(expectedContentHeader, testHeaders["Content-Type"]) {
		t.Errorf("Actual content type header %v differs from expected content type header %v", testHeaders["Content-Type"], expectedContentHeader)
	}
	addContentTypeHeader(testHeaders, urlEncodedUtf8)
	expectedContentHeader = "application/x-www-form-urlencoded; charset=utf-8"
	if !reflect.DeepEqual(expectedContentHeader, testHeaders["Content-Type"]) {
		t.Errorf("Actual content type header %v differs from expected content type header %v", testHeaders["Content-Type"], expectedContentHeader)
	}
}

func TestEncodeQueryParameters(t *testing.T) {
	testQueryParams := make(map[string]string)
	testQueryParams["scope"] = "openid user.read"
	testQueryParams["client_id"] = "clientID"
	testQueryParams["grant_type"] = "authorization_code"
	encodedQuery := encodeQueryParameters(testQueryParams)
	expectedQueryParams := "scope=openid+user.read&client_id=clientID&grant_type=authorization_code"
	encodedQueryList := strings.Split(encodedQuery, "&")
	expectedQueryList := strings.Split(expectedQueryParams, "&")
	sort.Strings(encodedQueryList)
	sort.Strings(expectedQueryList)
	if !reflect.DeepEqual(encodedQueryList, expectedQueryList) {
		t.Errorf("Actual encoded query %v differs from expected query %v", encodedQuery, expectedQueryParams)
	}
}

func TestGetUserRealm(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpManager: mockHTTPManager}
	url := "https://login.microsoftonline.com/common/UserRealm/username?api-version=1.0"
	authParams := &msalbase.AuthParametersInternal{
		Username:  "username",
		Endpoints: testAuthorityEndpoints,
	}
	httpResp := &msalHTTPManagerResponse{
		responseCode: 200,
		responseData: `{"domain_name" : "domain", "cloud_instance_name" : "cloudInst", "cloud_audience_urn" : "URN"}`,
	}
	mockHTTPManager.On("Get", url, testHeaders).Return(httpResp, nil)
	userRealm := &msalbase.UserRealm{
		DomainName:        "domain",
		CloudAudienceURN:  "URN",
		CloudInstanceName: "cloudInst",
	}
	actualRealm, err := wrm.GetUserRealm(authParams)
	if err != nil {
		t.Errorf("Error should be nil, instead it is %v", err)
	}
	if !reflect.DeepEqual(userRealm, actualRealm) {
		t.Errorf("Actual realm %+v differs from expected realm %+v", actualRealm, userRealm)
	}
}

func TestGetAccessTokenFromUsernamePassword(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpManager: mockHTTPManager}
	authParams := &msalbase.AuthParametersInternal{
		Username:  "username",
		Password:  "pass",
		Endpoints: testAuthorityEndpoints,
	}
	respData := `{"access_token":"secret", "expires_in":10, "ext_expires_in":10}`
	tokenResp := &msalbase.TokenResponse{
		AccessToken:  "secret",
		ExpiresOn:    time.Now().Add(time.Second * time.Duration(10)),
		ExtExpiresOn: time.Now().Add(time.Second * time.Duration(10)),
	}
	response := &msalHTTPManagerResponse{
		responseCode: 200,
		responseData: respData,
	}
	paramMap := map[string]string{
		"scope":       "openid offline_access profile",
		"grant_type":  msalbase.PasswordGrant,
		"username":    "username",
		"password":    "pass",
		"client_id":   "",
		"client_info": "1",
	}
	mockHTTPManager.On(
		"Post", "https://login.microsoftonline.com/v2.0/token", encodeQueryParameters(paramMap), testHeadersWURLUTF8).Return(response, nil)
	actualToken, err := wrm.GetAccessTokenFromUsernamePassword(authParams)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualToken.AccessToken, tokenResp.AccessToken) &&
		!reflect.DeepEqual(actualToken.ExpiresOn, tokenResp.ExpiresOn) &&
		!reflect.DeepEqual(actualToken.ExtExpiresOn, tokenResp.ExtExpiresOn) {
		t.Errorf("Actual token response %+v differs from expected token response %+v", actualToken, tokenResp)
	}
}

func TestGetAccessTokenFromSAMLGrant(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpManager: mockHTTPManager}
	authParams := &msalbase.AuthParametersInternal{
		Username:  "username",
		Password:  "pass",
		Endpoints: testAuthorityEndpoints,
	}
	respData := `{"access_token":"secret", "expires_in":10, "ext_expires_in":10}`
	response := &msalHTTPManagerResponse{
		responseCode: 200,
		responseData: respData,
	}
	tokenResp := &msalbase.TokenResponse{
		AccessToken:  "secret",
		ExpiresOn:    time.Now().Add(time.Second * time.Duration(10)),
		ExtExpiresOn: time.Now().Add(time.Second * time.Duration(10)),
	}
	samlGrant := &wstrust.SamlTokenInfo{
		AssertionType: wstrust.SamlV1,
		Assertion:     "hello",
	}
	encodedParams := "assertion=aGVsbG8%3D&client_id=&client_info=1&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Asaml1_1-bearer&password=pass&" +
		"scope=openid+offline_access+profile&username=username"
	mockHTTPManager.On(
		"Post", "https://login.microsoftonline.com/v2.0/token", encodedParams, testHeadersWURLUTF8).Return(response, nil)
	actualToken, err := wrm.GetAccessTokenFromSamlGrant(authParams, samlGrant)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualToken.AccessToken, tokenResp.AccessToken) &&
		!reflect.DeepEqual(actualToken.ExpiresOn, tokenResp.ExpiresOn) &&
		!reflect.DeepEqual(actualToken.ExtExpiresOn, tokenResp.ExtExpiresOn) {
		t.Errorf("Actual token response %+v differs from expected token response %+v", actualToken, tokenResp)
	}
}

func TestGetDeviceCodeResult(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpManager: mockHTTPManager}
	authParams := &msalbase.AuthParametersInternal{
		Endpoints: testAuthorityEndpoints,
	}
	respData := `{"user_code":"user", "device_code":"dev"}`
	response := &msalHTTPManagerResponse{
		responseCode: 200,
		responseData: respData,
	}
	mockHTTPManager.On(
		"Post", "https://login.microsoftonline.com/v2.0/devicecode",
		"client_id=&scope=openid+offline_access+profile", testHeadersWURLUTF8).Return(response, nil)
	_, err := wrm.GetDeviceCodeResult(authParams)
	if err != nil {
		t.Errorf("Error should be nil, but is %v", err)
	}
}

func TestGetAccessTokenFromAuthCode(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpManager: mockHTTPManager}
	authParams := &msalbase.AuthParametersInternal{
		Endpoints: testAuthorityEndpoints,
	}
	respData := `{"access_token":"secret", "expires_in":10, "ext_expires_in":10}`
	response := &msalHTTPManagerResponse{
		responseCode: 200,
		responseData: respData,
	}
	tokenResp := &msalbase.TokenResponse{
		AccessToken:  "secret",
		ExpiresOn:    time.Now().Add(time.Second * time.Duration(10)),
		ExtExpiresOn: time.Now().Add(time.Second * time.Duration(10)),
	}
	params := "client_id=&client_info=1&code=code&code_verifier=ver&" +
		"grant_type=authorization_code&redirect_uri=&scope=openid+offline_access+profile"
	mockHTTPManager.On(
		"Post", "https://login.microsoftonline.com/v2.0/token", params, testHeadersWURLUTF8).Return(response, nil)
	actualToken, err := wrm.GetAccessTokenFromAuthCode(authParams, "code", "ver", map[string]string{})
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualToken.AccessToken, tokenResp.AccessToken) &&
		!reflect.DeepEqual(actualToken.ExpiresOn, tokenResp.ExpiresOn) &&
		!reflect.DeepEqual(actualToken.ExtExpiresOn, tokenResp.ExtExpiresOn) {
		t.Errorf("Actual token response %+v differs from expected token response %+v", actualToken, tokenResp)
	}
}

func TestGetAccessTokenFromRefreshToken(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpManager: mockHTTPManager}
	authParams := &msalbase.AuthParametersInternal{
		Endpoints: testAuthorityEndpoints,
	}
	respData := `{"access_token":"secret", "expires_in":10, "ext_expires_in":10}`
	response := &msalHTTPManagerResponse{
		responseCode: 200,
		responseData: respData,
	}
	tokenResp := &msalbase.TokenResponse{
		AccessToken:  "secret",
		ExpiresOn:    time.Now().Add(time.Second * time.Duration(10)),
		ExtExpiresOn: time.Now().Add(time.Second * time.Duration(10)),
	}
	params := "client_id=&client_info=1&grant_type=refresh_token&refresh_token=secret&scope=openid+offline_access+profile"
	mockHTTPManager.On(
		"Post", "https://login.microsoftonline.com/v2.0/token", params, testHeadersWURLUTF8).Return(response, nil)
	actualToken, err := wrm.GetAccessTokenFromRefreshToken(authParams, "secret", map[string]string{})
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualToken.AccessToken, tokenResp.AccessToken) &&
		!reflect.DeepEqual(actualToken.ExpiresOn, tokenResp.ExpiresOn) &&
		!reflect.DeepEqual(actualToken.ExtExpiresOn, tokenResp.ExtExpiresOn) {
		t.Errorf("Actual token response %+v differs from expected token response %+v", actualToken, tokenResp)
	}
}

func TestGetAccessTokenWithClientSecret(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpManager: mockHTTPManager}
	authParams := &msalbase.AuthParametersInternal{
		Endpoints: testAuthorityEndpoints,
	}
	respData := `{"access_token":"secret", "expires_in":10, "ext_expires_in":10}`
	response := &msalHTTPManagerResponse{
		responseCode: 200,
		responseData: respData,
	}
	tokenResp := &msalbase.TokenResponse{
		AccessToken:  "secret",
		ExpiresOn:    time.Now().Add(time.Second * time.Duration(10)),
		ExtExpiresOn: time.Now().Add(time.Second * time.Duration(10)),
	}
	params := "client_id=&client_secret=csecret&grant_type=client_credentials&scope=openid+offline_access+profile"
	mockHTTPManager.On(
		"Post", "https://login.microsoftonline.com/v2.0/token", params, testHeadersWURLUTF8).Return(response, nil)
	actualToken, err := wrm.GetAccessTokenWithClientSecret(authParams, "csecret")
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualToken.AccessToken, tokenResp.AccessToken) &&
		!reflect.DeepEqual(actualToken.ExpiresOn, tokenResp.ExpiresOn) &&
		!reflect.DeepEqual(actualToken.ExtExpiresOn, tokenResp.ExtExpiresOn) {
		t.Errorf("Actual token response %+v differs from expected token response %+v", actualToken, tokenResp)
	}
}

func TestGetAccessTokenWithAssertion(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpManager: mockHTTPManager}
	authParams := &msalbase.AuthParametersInternal{
		Endpoints: testAuthorityEndpoints,
	}
	respData := `{"access_token":"secret", "expires_in":10, "ext_expires_in":10}`
	response := &msalHTTPManagerResponse{
		responseCode: 200,
		responseData: respData,
	}
	tokenResp := &msalbase.TokenResponse{
		AccessToken:  "secret",
		ExpiresOn:    time.Now().Add(time.Second * time.Duration(10)),
		ExtExpiresOn: time.Now().Add(time.Second * time.Duration(10)),
	}
	params := "client_assertion=assertion&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer" +
		"&client_info=1&grant_type=client_credentials&scope=openid+offline_access+profile"
	mockHTTPManager.On(
		"Post", "https://login.microsoftonline.com/v2.0/token", params, testHeadersWURLUTF8).Return(response, nil)
	actualToken, err := wrm.GetAccessTokenWithAssertion(authParams, "assertion")
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualToken.AccessToken, tokenResp.AccessToken) &&
		!reflect.DeepEqual(actualToken.ExpiresOn, tokenResp.ExpiresOn) &&
		!reflect.DeepEqual(actualToken.ExtExpiresOn, tokenResp.ExtExpiresOn) {
		t.Errorf("Actual token response %+v differs from expected token response %+v", actualToken, tokenResp)
	}
}

func TestGetAadInstanceDiscoveryResponse(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpManager: mockHTTPManager}
	authInfo := &msalbase.AuthorityInfo{
		Host:   "login.microsoftonline.com",
		Tenant: "tenant",
	}
	respData := `{}`
	response := &msalHTTPManagerResponse{
		responseCode: 200,
		responseData: respData,
	}
	instanceDiscEndpoint := "https://login.microsoftonline.com/common/discovery/instance?api-version=1.1&" +
		"authorization_endpoint=https%3A%2F%2Flogin.microsoftonline.com%2Ftenant%2Foauth2%2Fv2.0%2Fauthorize"
	var params map[string]string = nil
	mockHTTPManager.On("Get", instanceDiscEndpoint, params).Return(response, nil)
	expIDR := &requests.InstanceDiscoveryResponse{}
	actIDR, err := wrm.GetAadinstanceDiscoveryResponse(authInfo)

	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(expIDR, actIDR) {
		t.Errorf("Actual instance discovery response %+v differs from expected instance discovery response %+v", actIDR, expIDR)
	}
}

func TestGetTenantDiscoveryResponse(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpManager: mockHTTPManager}
	respData := `{}`
	response := &msalHTTPManagerResponse{
		responseCode: 200,
		responseData: respData,
	}
	openIDEndpoint := "endpoint"
	var params map[string]string = nil
	mockHTTPManager.On("Get", openIDEndpoint, params).Return(response, nil)
	_, err := wrm.GetTenantDiscoveryResponse(openIDEndpoint)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}
