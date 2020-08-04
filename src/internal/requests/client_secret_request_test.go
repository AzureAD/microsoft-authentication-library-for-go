// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

func TestClientSecretReqExecute(t *testing.T) {
	var secret = "secret"
	wrm := new(MockWebRequestManager)
	var clientSecretRequest = &ClientSecretRequest{
		webRequestManager: wrm,
		authParameters:    testAuthParams,
		clientSecret:      secret,
	}
	tdr := &TenantDiscoveryResponse{
		AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
		TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
		Issuer:                "https://login.microsoftonline.com/v2.0",
	}
	actualTokenResp := &msalbase.TokenResponse{}
	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration").Return(tdr, nil)
	wrm.On("GetAccessTokenWithClientSecret", clientSecretRequest.authParameters, secret).Return(actualTokenResp, nil)
	_, err := clientSecretRequest.Execute()
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}
