// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package integrationtests

import (
	"context"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal"
)

var labClientInstance = &labClient{}

func AcquireTokenByUsernamePasswordCommonAAD(t *testing.T, user user, authority string, scope []string, appID string) {
	options := msal.DefaultPublicClientApplicationOptions()
	options.Authority = authority
	publicClientApp, err := msal.NewPublicClientApplication(appID, &options)
	if err != nil {
		panic(err)
	}
	result, err := publicClientApp.AcquireTokenByUsernamePassword(
		context.Background(),
		scope,
		user.Upn,
		user.Password,
	)
	if err != nil {
		t.Error(err)
	}
	if result.AccessToken == "" {
		t.Error("No access token found")
	}
	if result.Account.GetUsername() != user.Upn {
		t.Errorf("Incorrect user account")
	}
}
func TestAcquireTokenByUsernamePasswordManaged(t *testing.T) {
	user := labClientInstance.getUser(map[string]string{"usertype": "cloud"})
	AcquireTokenByUsernamePasswordCommonAAD(t, user, OrganizationsAuthority, []string{GraphDefaultScope}, user.AppID)
}

func TestAcquireTokenByUsernamePasswordFederatedADFSv4(t *testing.T) {
	user := labClientInstance.getUser(map[string]string{"usertype": "federated", "federationProvider": "ADFSv4"})
	AcquireTokenByUsernamePasswordCommonAAD(t, user, OrganizationsAuthority, []string{GraphDefaultScope}, user.AppID)
}

func TestAcquireTokenByUsernamePasswordFederatedADFSv3(t *testing.T) {
	user := labClientInstance.getUser(map[string]string{"usertype": "federated", "federationProvider": "ADFSv3"})
	AcquireTokenByUsernamePasswordCommonAAD(t, user, OrganizationsAuthority, []string{GraphDefaultScope}, user.AppID)
}

func TestAcquireTokenByUsernamePasswordFederatedADFSv2(t *testing.T) {
	user := labClientInstance.getUser(map[string]string{"usertype": "federated", "federationProvider": "ADFSv2"})
	AcquireTokenByUsernamePasswordCommonAAD(t, user, OrganizationsAuthority, []string{GraphDefaultScope}, user.AppID)
}
