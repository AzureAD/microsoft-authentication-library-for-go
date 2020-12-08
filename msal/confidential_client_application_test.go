// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"context"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
	"github.com/stretchr/testify/mock"
)

func TestAcquireTokenByClientCredential(t *testing.T) {
	wrm := new(requests.MockWebRequestManager)
	fm := &fakeManager{}

	cred, _ := msalbase.CreateClientCredentialFromSecret("client_secret")
	cca := &ConfidentialClientApplication{
		clientApplication: newTestApplication(fm, wrm),
		clientCredential:  cred,
	}

	wrm.On(
		"GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration",
	).Return(tdr, nil)

	wrm.On(
		"GetAccessTokenWithClientSecret",
		mock.AnythingOfType("msalbase.AuthParametersInternal"),
		"client_secret",
	).Return(msalbase.TokenResponse{}, nil)

	_, err := cca.AcquireTokenByClientCredential(context.Background(), []string{"openid"})
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}
