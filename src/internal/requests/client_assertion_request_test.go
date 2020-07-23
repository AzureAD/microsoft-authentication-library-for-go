// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

var clientAssertion = &msalbase.ClientAssertion{ClientAssertionJWT: "hello"}
var clientAssertionReq = &ClientAssertionRequest{
	webRequestManager: wrm,
	authParameters:    testAuthParams,
	clientAssertion:   clientAssertion,
}

func TestClientAssertionReqExecute(t *testing.T) {
	tdr := &TenantDiscoveryResponse{
		AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
		TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
		Issuer:                "https://login.microsoftonline.com/v2.0",
	}
	actualTokenResp := &msalbase.TokenResponse{}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	wrm.On("GetAccessTokenWithAssertion", clientAssertionReq.authParameters, "hello").Return(actualTokenResp, nil)
	_, err := clientAssertionReq.Execute()
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}
