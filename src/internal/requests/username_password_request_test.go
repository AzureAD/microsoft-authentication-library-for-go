// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package requests

import (
	"errors"
	"reflect"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

var testUPAuthorityInfo, _ = msalbase.CreateAuthorityInfoFromAuthorityUri("https://login.microsoftonline.com/v2.0/", true)
var testUPAuthParams = msalbase.CreateAuthParametersInternal("clientID", testUPAuthorityInfo)
var upWRM = new(MockWebRequestManager)
var upCacheManager = new(MockCacheManager)
var usernamePassRequest = &UsernamePasswordRequest{
	cacheManager:   upCacheManager,
	authParameters: testUPAuthParams,
}

var tdr = &TenantDiscoveryResponse{
	AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
	TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
	Issuer:                "https://login.microsoftonline.com/v2.0",
}

var managedUserRealm = &msalbase.UserRealm{
	AccountType: "Managed",
}

var errorUserRealm = &msalbase.UserRealm{
	AccountType: "",
}

func TestUsernamePassExecuteWithManaged(t *testing.T) {
	upWRM = new(MockWebRequestManager)
	usernamePassRequest.webRequestManager = upWRM
	upWRM.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	upWRM.On("GetUserRealm", usernamePassRequest.authParameters).Return(managedUserRealm, nil)
	actualTokenResp := &msalbase.TokenResponse{}
	upWRM.On("GetAccessTokenFromUsernamePassword", usernamePassRequest.authParameters).Return(actualTokenResp, nil)
	_, err := usernamePassRequest.Execute()
	if err != nil {
		t.Errorf("Error is supposed to be nil, instead it is %v", err)
	}
}

func TestUsernamePassExecuteWithAcctError(t *testing.T) {
	newUpWRM := new(MockWebRequestManager)
	usernamePassRequest.webRequestManager = newUpWRM
	newUpWRM.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	newUpWRM.On("GetUserRealm", usernamePassRequest.authParameters).Return(errorUserRealm, nil)
	_, acctError := usernamePassRequest.Execute()
	expectedErrorMessage := "Unknown account type"
	if acctError == nil {
		t.Errorf("Error is nil, should be %v", errors.New(expectedErrorMessage))
	}
	if !reflect.DeepEqual(acctError.Error(), expectedErrorMessage) {
		t.Errorf("Actual error message %v differs from expected error message %v", acctError.Error(), expectedErrorMessage)
	}
}
