// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/wstrust"
	"github.com/kylelemons/godebug/pretty"
)

const (
	fakeTokenResp         = `{"access_token":"secret", "expires_in":10, "ext_expires_in":10}`
	tokenEndpointURL      = "https://login.microsoftonline.com/v2.0/token"
	deviceCodeEndpointURL = "https://login.microsoftonline.com/v2.0/devicecode"
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
	testHeaders := http.Header{}
	addContentTypeHeader(testHeaders, soapXMLUtf8)
	expectedContentHeader := "application/soap+xml; charset=utf-8"
	if !reflect.DeepEqual(expectedContentHeader, testHeaders.Get("Content-Type")) {
		t.Errorf("Actual content type header %v differs from expected content type header %v", testHeaders["Content-Type"], expectedContentHeader)
	}
	addContentTypeHeader(testHeaders, urlEncodedUtf8)
	expectedContentHeader = "application/x-www-form-urlencoded; charset=utf-8"
	if !reflect.DeepEqual(expectedContentHeader, testHeaders.Get("Content-Type")) {
		t.Errorf("Actual content type header %v differs from expected content type header %v", testHeaders["Content-Type"], expectedContentHeader)
	}
}

func createFakeRequest(method, u string) *http.Request {
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		panic(err)
	}
	return req
}

func createFakeRequestWithBody(method, u, b string) *http.Request {
	req, err := http.NewRequest(method, u, strings.NewReader(b))
	if err != nil {
		panic(err)
	}
	// reflect.DeepEqual() is used under-the-hood and will always return false when
	// comparing non-nil funcs.  set this to nil to work around this behavior.
	req.GetBody = nil
	return req
}

func createFakeResponse(status int, body string) *http.Response {
	resp := &http.Response{
		StatusCode: status,
	}
	if body != "" {
		resp.Body = ioutil.NopCloser(strings.NewReader(body))
	}
	return resp
}

func addTestHeaders(req *http.Request, headers map[string]string) {
	for k, v := range headers {
		req.Header.Set(k, v)
	}
}

func TestGetUserRealm(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpClient: mockHTTPManager}
	authParams := msalbase.AuthParametersInternal{
		Username:  "username",
		Endpoints: testAuthorityEndpoints,
	}
	httpResp := createFakeResponse(http.StatusOK, `{"domain_name" : "domain", "cloud_instance_name" : "cloudInst", "cloud_audience_urn" : "URN"}`)
	req := createFakeRequest(http.MethodGet, "https://login.microsoftonline.com/common/UserRealm/username?api-version=1.0")
	addTestHeaders(req, testHeaders)
	mockHTTPManager.On("Do", req).Return(httpResp, nil)
	want := msalbase.UserRealm{
		DomainName:        "domain",
		CloudAudienceURN:  "URN",
		CloudInstanceName: "cloudInst",
	}
	got, err := wrm.GetUserRealm(context.Background(), authParams)
	if err != nil {
		t.Fatalf("TestGetUserRealm: got err == %s, want err == nil", err)
	}
	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestGetUserRealm: -want/+got:\n%s", diff)
	}
}

func TestGetAccessTokenFromUsernamePassword(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpClient: mockHTTPManager}
	authParams := msalbase.AuthParametersInternal{
		Username:  "username",
		Password:  "pass",
		Endpoints: testAuthorityEndpoints,
	}
	tokenResp := msalbase.TokenResponse{
		AccessToken:  "secret",
		ExpiresOn:    time.Now().Add(time.Second * time.Duration(10)),
		ExtExpiresOn: time.Now().Add(time.Second * time.Duration(10)),
	}
	response := createFakeResponse(http.StatusOK, fakeTokenResp)
	paramMap := url.Values{}
	paramMap.Set("scope", "openid offline_access profile")
	paramMap.Set("grant_type", msalbase.PasswordGrant)
	paramMap.Set("username", "username")
	paramMap.Set("password", "pass")
	paramMap.Set("client_id", "")
	paramMap.Set("client_info", "1")
	req := createFakeRequestWithBody(http.MethodPost, tokenEndpointURL, paramMap.Encode())
	addTestHeaders(req, testHeadersWURLUTF8)
	mockHTTPManager.On("Do", req).Return(response, nil)

	actualToken, err := wrm.GetAccessTokenFromUsernamePassword(context.Background(), authParams)
	if err != nil {
		t.Fatalf("Error should be nil, but it is %v", err)
	}
	// TODO(msal expert): I made this nicer here and below, but...
	// this tests looks like it requires all 3 things not to match in
	// order for the tests to fail. Did we mean to fail if any of these
	// were different?  Could we just do a single compare and if any field
	// is different just error?
	if actualToken.AccessToken != tokenResp.AccessToken &&
		!actualToken.ExpiresOn.Equal(tokenResp.ExpiresOn) &&
		!actualToken.ExtExpiresOn.Equal(tokenResp.ExtExpiresOn) {
		t.Errorf("Actual token response %+v differs from expected token response %+v", actualToken, tokenResp)
	}
}

func TestGetAccessTokenFromSAMLGrant(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpClient: mockHTTPManager}
	authParams := msalbase.AuthParametersInternal{
		Username:  "username",
		Password:  "pass",
		Endpoints: testAuthorityEndpoints,
	}
	response := createFakeResponse(http.StatusOK, fakeTokenResp)
	tokenResp := msalbase.TokenResponse{
		AccessToken:  "secret",
		ExpiresOn:    time.Now().Add(time.Second * time.Duration(10)),
		ExtExpiresOn: time.Now().Add(time.Second * time.Duration(10)),
	}
	samlGrant := wstrust.SamlTokenInfo{
		AssertionType: msalbase.SAMLV1Grant,
		Assertion:     "hello",
	}
	req := createFakeRequestWithBody(http.MethodPost, tokenEndpointURL, "assertion=aGVsbG8%3D&client_id=&client_info=1&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Asaml1_1-bearer&password=pass&"+
		"scope=openid+offline_access+profile&username=username")
	addTestHeaders(req, testHeadersWURLUTF8)
	mockHTTPManager.On("Do", req).Return(response, nil)

	actualToken, err := wrm.GetAccessTokenFromSamlGrant(context.Background(), authParams, samlGrant)
	if err != nil {
		t.Fatalf("Error should be nil, but it is %v", err)
	}
	if actualToken.AccessToken != tokenResp.AccessToken &&
		!actualToken.ExpiresOn.Equal(tokenResp.ExpiresOn) &&
		!actualToken.ExtExpiresOn.Equal(tokenResp.ExtExpiresOn) {
		t.Errorf("Actual token response %+v differs from expected token response %+v", actualToken, tokenResp)
	}
}

func TestGetDeviceCodeResult(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpClient: mockHTTPManager}
	authParams := msalbase.AuthParametersInternal{
		Endpoints: testAuthorityEndpoints,
	}
	response := createFakeResponse(http.StatusOK, `{"user_code":"user", "device_code":"dev"}`)
	req := createFakeRequestWithBody(http.MethodPost, deviceCodeEndpointURL, "client_id=&scope=openid+offline_access+profile")
	addTestHeaders(req, testHeadersWURLUTF8)
	mockHTTPManager.On("Do", req).Return(response, nil)

	// TODO(jdoak): suspicious of tests that are just looking at err
	// and not the value.
	_, err := wrm.GetDeviceCodeResult(context.Background(), authParams)
	if err != nil {
		t.Errorf("Error should be nil, but is %v", err)
	}
}

func TestGetAccessTokenFromAuthCode(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpClient: mockHTTPManager}
	authParams := msalbase.AuthParametersInternal{
		Endpoints: testAuthorityEndpoints,
	}
	response := createFakeResponse(http.StatusOK, fakeTokenResp)
	tokenResp := msalbase.TokenResponse{
		AccessToken:  "secret",
		ExpiresOn:    time.Now().Add(time.Second * time.Duration(10)),
		ExtExpiresOn: time.Now().Add(time.Second * time.Duration(10)),
	}
	req := createFakeRequestWithBody(http.MethodPost, tokenEndpointURL, "client_id=&client_info=1&code=code&code_verifier=ver&grant_type=authorization_code&redirect_uri=&scope=openid+offline_access+profile")
	addTestHeaders(req, testHeadersWURLUTF8)
	mockHTTPManager.On("Do", req).Return(response, nil)

	actualToken, err := wrm.GetAccessTokenFromAuthCode(context.Background(), authParams, "code", "ver", url.Values{})
	if err != nil {
		t.Fatalf("Error should be nil, but it is %v", err)
	}
	if actualToken.AccessToken != tokenResp.AccessToken &&
		!actualToken.ExpiresOn.Equal(tokenResp.ExpiresOn) &&
		!actualToken.ExtExpiresOn.Equal(tokenResp.ExtExpiresOn) {
		t.Errorf("Actual token response %+v differs from expected token response %+v", actualToken, tokenResp)
	}
}

func TestGetAccessTokenFromRefreshToken(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpClient: mockHTTPManager}
	authParams := msalbase.AuthParametersInternal{
		Endpoints: testAuthorityEndpoints,
	}
	response := createFakeResponse(http.StatusOK, fakeTokenResp)
	tokenResp := msalbase.TokenResponse{
		AccessToken:  "secret",
		ExpiresOn:    time.Now().Add(time.Second * time.Duration(10)),
		ExtExpiresOn: time.Now().Add(time.Second * time.Duration(10)),
	}
	req := createFakeRequestWithBody(http.MethodPost, tokenEndpointURL, "client_id=&client_info=1&grant_type=refresh_token&refresh_token=secret&scope=openid+offline_access+profile")
	addTestHeaders(req, testHeadersWURLUTF8)
	mockHTTPManager.On("Do", req).Return(response, nil)

	actualToken, err := wrm.GetAccessTokenFromRefreshToken(context.Background(), authParams, "secret", url.Values{})
	if err != nil {
		t.Fatalf("Error should be nil, but it is %v", err)
	}
	if actualToken.AccessToken != tokenResp.AccessToken &&
		!actualToken.ExpiresOn.Equal(tokenResp.ExpiresOn) &&
		!actualToken.ExtExpiresOn.Equal(tokenResp.ExtExpiresOn) {
		t.Errorf("Actual token response %+v differs from expected token response %+v", actualToken, tokenResp)
	}
}

func TestGetAccessTokenWithClientSecret(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpClient: mockHTTPManager}
	authParams := msalbase.AuthParametersInternal{
		Endpoints: testAuthorityEndpoints,
	}
	response := createFakeResponse(http.StatusOK, fakeTokenResp)
	tokenResp := msalbase.TokenResponse{
		AccessToken:  "secret",
		ExpiresOn:    time.Now().Add(time.Second * time.Duration(10)),
		ExtExpiresOn: time.Now().Add(time.Second * time.Duration(10)),
	}
	req := createFakeRequestWithBody(http.MethodPost, tokenEndpointURL, "client_id=&client_secret=csecret&grant_type=client_credentials&scope=openid+offline_access+profile")
	addTestHeaders(req, testHeadersWURLUTF8)
	mockHTTPManager.On("Do", req).Return(response, nil)

	actualToken, err := wrm.GetAccessTokenWithClientSecret(context.Background(), authParams, "csecret")
	if err != nil {
		t.Fatalf("Error should be nil, but it is %v", err)
	}
	if actualToken.AccessToken != tokenResp.AccessToken &&
		!actualToken.ExpiresOn.Equal(tokenResp.ExpiresOn) &&
		!actualToken.ExtExpiresOn.Equal(tokenResp.ExtExpiresOn) {
		t.Errorf("Actual token response %+v differs from expected token response %+v", actualToken, tokenResp)
	}
}

func TestGetAccessTokenWithAssertion(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpClient: mockHTTPManager}
	authParams := msalbase.AuthParametersInternal{
		Endpoints: testAuthorityEndpoints,
	}
	response := createFakeResponse(http.StatusOK, fakeTokenResp)
	tokenResp := msalbase.TokenResponse{
		AccessToken:  "secret",
		ExpiresOn:    time.Now().Add(time.Second * time.Duration(10)),
		ExtExpiresOn: time.Now().Add(time.Second * time.Duration(10)),
	}
	req := createFakeRequestWithBody(http.MethodPost, tokenEndpointURL, "client_assertion=assertion&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_info=1&grant_type=client_credentials&scope=openid+offline_access+profile")
	addTestHeaders(req, testHeadersWURLUTF8)
	mockHTTPManager.On("Do", req).Return(response, nil)
	actualToken, err := wrm.GetAccessTokenWithAssertion(context.Background(), authParams, "assertion")
	if err != nil {
		t.Fatalf("Error should be nil, but it is %v", err)
	}
	if actualToken.AccessToken != tokenResp.AccessToken &&
		!actualToken.ExpiresOn.Equal(tokenResp.ExpiresOn) &&
		!actualToken.ExtExpiresOn.Equal(tokenResp.ExtExpiresOn) {
		t.Errorf("Actual token response %+v differs from expected token response %+v", actualToken, tokenResp)
	}
}

func TestGetAadInstanceDiscoveryResponse(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpClient: mockHTTPManager}
	authInfo := msalbase.AuthorityInfo{
		Host:   "login.microsoftonline.com",
		Tenant: "tenant",
	}
	response := createFakeResponse(http.StatusOK, `{}`)
	req := createFakeRequest(http.MethodGet, "https://login.microsoftonline.com/common/discovery/instance?api-version=1.1&authorization_endpoint=https%3A%2F%2Flogin.microsoftonline.com%2Ftenant%2Foauth2%2Fv2.0%2Fauthorize")
	mockHTTPManager.On("Do", req).Return(response, nil)
	expIDR := &requests.InstanceDiscoveryResponse{}
	actIDR, err := wrm.GetAadinstanceDiscoveryResponse(context.Background(), authInfo)
	if err != nil {
		t.Fatalf("Error should be nil, but it is %v", err)
	}
	if diff := pretty.Compare(expIDR, actIDR); diff != "" {
		t.Errorf("TestGetAadInstanceDiscoveryResponse: -want/+got:\n%s", diff)
	}
}

func TestGetTenantDiscoveryResponse(t *testing.T) {
	mockHTTPManager := new(mockHTTPManager)
	wrm := &defaultWebRequestManager{httpClient: mockHTTPManager}
	response := createFakeResponse(http.StatusOK, `{}`)
	openIDEndpoint := "endpoint"
	req := createFakeRequest(http.MethodGet, openIDEndpoint)
	mockHTTPManager.On("Do", req).Return(response, nil)
	_, err := wrm.GetTenantDiscoveryResponse(context.Background(), openIDEndpoint)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}
