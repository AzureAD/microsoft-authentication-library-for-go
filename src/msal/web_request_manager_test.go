// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

func TestAddContentTypeHeader(t *testing.T) {
	testHeaders := make(map[string]string)
	addContentTypeHeader(testHeaders, SoapXMLUtf8)
	expectedContentHeader := "application/soap+xml; charset=utf-8"
	if !reflect.DeepEqual(expectedContentHeader, testHeaders["Content-Type"]) {
		t.Errorf("Actual content type header %v differs from expected content type header %v", testHeaders["Content-Type"], expectedContentHeader)
	}
	addContentTypeHeader(testHeaders, URLEncodedUtf8)
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
	mockHTTPManager := new(MockHTTPManager)
	wrm := &WebRequestManager{httpManager: mockHTTPManager}
	url := "https://login.microsoftonline.com/common/UserRealm/username?api-version=1.0"
	authParams := &msalbase.AuthParametersInternal{
		Username:  "username",
		Endpoints: testAuthorityEndpoints,
	}
	httpResp := &HTTPManagerResponse{
		responseCode: 200,
		responseData: `{"domain_name" : "domain", "cloud_instance_name" : "cloudInst", "cloud_audience_urn" : "URN"}`,
	}
	mockHTTPManager.On("Get", url, getAadHeaders(authParams)).Return(httpResp, nil)
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
