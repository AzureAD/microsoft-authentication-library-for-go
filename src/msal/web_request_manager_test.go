// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"reflect"
	"sort"
	"strings"
	"testing"
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

func TestExchangeGrantForToken(t *testing.T) {

}
