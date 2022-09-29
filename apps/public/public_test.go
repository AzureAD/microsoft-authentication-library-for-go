// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package public

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/fake"
)

var tokenScope = []string{"the_scope"}

func fakeBrowserOpenURL(authURL string) error {
	// we will get called with the URL for requesting an auth code
	u, err := url.Parse(authURL)
	if err != nil {
		return err
	}
	// validate the URL content
	q := u.Query()
	if q.Get("code_challenge") == "" {
		return errors.New("missing query param 'code_challenge")
	}
	if m := q.Get("code_challenge_method"); m != "S256" {
		return fmt.Errorf("unexpected code_challenge_method '%s'", m)
	}
	if q.Get("prompt") == "" {
		return errors.New("missing query param 'prompt")
	}
	state := q.Get("state")
	if state == "" {
		return errors.New("missing query param 'state'")
	}
	redirect := q.Get("redirect_uri")
	if redirect == "" {
		return errors.New("missing query param 'redirect_uri'")
	}
	// now send the info to our local redirect server
	resp, err := http.DefaultClient.Get(redirect + fmt.Sprintf("/?state=%s&code=fake_auth_code", state))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	return nil
}

func TestAcquireTokenInteractive(t *testing.T) {
	browserOpenURL = fakeBrowserOpenURL
	client, err := New("some_client_id")
	if err != nil {
		t.Fatal(err)
	}
	client.base.Token.AccessTokens = &fake.AccessTokens{}
	client.base.Token.Authority = &fake.Authority{}
	client.base.Token.Resolver = &fake.ResolveEndpoints{}
	client.base.Token.WSTrust = &fake.WSTrust{}
	_, err = client.AcquireTokenInteractive(context.Background(), []string{"the_scope"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAcquireTokenSilentTenants(t *testing.T) {
	tenants := []string{"a", "b"}
	lmo := "login.microsoftonline.com"
	mockClient := mock.Client{}
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenants[0])))
	client, err := New("client-id", WithHTTPClient(&mockClient))
	if err != nil {
		t.Fatal(err)
	}
	clientInfo := base64.RawStdEncoding.EncodeToString([]byte(`{"uid":"uid","utid":"utid"}`))
	ctx := context.Background()
	accounts := make([]Account, len(tenants))
	// cache an access token for each tenant. To simplify determining their provenance below, the value of each token is the ID of the tenant that provided it.
	for i, tenant := range tenants {
		if _, err = client.AcquireTokenSilent(ctx, tokenScope, WithTenantID(tenant)); err == nil {
			t.Fatal("silent auth should fail because the cache is empty")
		}
		mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
		mockClient.AppendResponse(mock.WithBody([]byte(`{"account_type":"Managed","cloud_audience_urn":"urn","cloud_instance_name":"...","domain_name":"..."}`)))
		mockClient.AppendResponse(mock.WithBody(
			mock.GetAccessTokenBody(tenant, mock.GetIDToken(tenant, fmt.Sprintf("https://%s/%s", lmo, tenant)), "rt-"+tenant, clientInfo, 3600)),
		)
		ar, err := client.AcquireTokenByUsernamePassword(ctx, tokenScope, "username", "password", WithTenantID(tenant))
		if err != nil {
			t.Fatal(err)
		}
		accounts[i] = ar.Account
	}
	// cache should return the correct access token for each tenant
	for i, account := range accounts {
		if account.Realm != tenants[i] {
			t.Fatalf(`unexpected realm "%s"`, account.Realm)
		}
		otherTenant := tenants[(i+1)%len(tenants)]
		for _, test := range []struct {
			desc, expected string
			opts           []AcquireSilentOption
		}{
			{"account only", account.Realm, []AcquireSilentOption{WithSilentAccount(account)}},
			{"matching account and tenant", account.Realm, []AcquireSilentOption{WithSilentAccount(account), WithTenantID(account.Realm)}},
			{"tenant overriding account", otherTenant, []AcquireSilentOption{WithSilentAccount(account), WithTenantID(otherTenant)}},
		} {
			t.Run(test.desc, func(t *testing.T) {
				ar, err := client.AcquireTokenSilent(ctx, tokenScope, test.opts...)
				if err != nil {
					t.Fatal(err)
				}
				if ar.AccessToken != test.expected {
					t.Fatalf(`expected "%s", got "%s"`, test.expected, ar.AccessToken)
				}
			})
		}
	}
}

func TestAcquireTokenWithTenantID(t *testing.T) {
	// replacing browserOpenURL with a fake for the duration of this test enables testing AcquireTokenInteractive
	realBrowserOpenURL := browserOpenURL
	defer func() { browserOpenURL = realBrowserOpenURL }()
	browserOpenURL = fakeBrowserOpenURL

	clientInfo := base64.RawStdEncoding.EncodeToString([]byte(`{"uid":"uid","utid":"utid"}`))
	uuid1 := "00000000-0000-0000-0000-000000000000"
	uuid2 := strings.ReplaceAll(uuid1, "0", "1")
	lmo := "login.microsoftonline.com"
	host := fmt.Sprintf("https://%s/", lmo)
	for _, test := range []struct {
		authority, expectedAuthority, tenant string
		expectError                          bool
	}{
		{authority: host + "common", tenant: uuid1, expectedAuthority: host + uuid1},
		{authority: host + "consumers", tenant: uuid1, expectedAuthority: host + uuid1},
		{authority: host + "organizations", tenant: uuid1, expectedAuthority: host + uuid1},
		{authority: host + uuid1, tenant: uuid2, expectedAuthority: host + uuid2},
		{authority: host + uuid1, tenant: "common", expectError: true},
		{authority: host + uuid1, tenant: "organizations", expectError: true},
	} {
		for _, flow := range []string{"authcode", "devicecode", "interactive", "password"} {
			t.Run(flow, func(t *testing.T) {
				mockClient := mock.Client{}
				if flow == "obo" {
					// TODO: OBO does instance discovery twice before first token request https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/351
					mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, test.tenant)))
				}
				validated := false
				mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, test.tenant)))
				mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, test.tenant)))
				if flow == "devicecode" {
					mockClient.AppendResponse(mock.WithBody([]byte(`{"device_code":"...","expires_in":600}`)))
				} else if flow == "password" {
					// user realm metadata
					mockClient.AppendResponse(mock.WithBody([]byte(`{"account_type":"Managed","cloud_audience_urn":"urn","cloud_instance_name":"...","domain_name":"..."}`)))
				}

				mockClient.AppendResponse(
					mock.WithBody(mock.GetAccessTokenBody("*", mock.GetIDToken(test.tenant, test.authority), "rt", clientInfo, 3600)),
					mock.WithCallback(func(r *http.Request) {
						validated = true
						if u := r.URL.String(); !(strings.HasPrefix(u, test.expectedAuthority) && strings.HasSuffix(u, "/token")) {
							t.Fatalf(`unexpected token request URL "%s"`, u)
						}
					}),
				)
				client, err := New("client-id", WithAuthority(test.authority), WithHTTPClient(&mockClient))
				if err != nil {
					t.Fatal(err)
				}
				ctx := context.Background()
				if _, err = client.AcquireTokenSilent(ctx, tokenScope, WithTenantID(test.tenant)); err == nil {
					t.Fatal("silent auth should fail because the cache is empty")
				}

				var ar AuthResult
				var dc DeviceCode
				switch flow {
				case "authcode":
					ar, err = client.AcquireTokenByAuthCode(ctx, "auth code", "https://localhost", tokenScope, WithTenantID(test.tenant))
				case "devicecode":
					dc, err = client.AcquireTokenByDeviceCode(ctx, tokenScope, WithTenantID(test.tenant))
				case "interactive":
					ar, err = client.AcquireTokenInteractive(ctx, tokenScope, WithTenantID(test.tenant))
				case "password":
					ar, err = client.AcquireTokenByUsernamePassword(ctx, tokenScope, "username", "password", WithTenantID(test.tenant))
				default:
					t.Fatalf("no test for " + flow)
				}
				if err != nil {
					if test.expectError {
						return
					}
					t.Fatal(err)
				}
				if flow == "devicecode" {
					if ar, err = dc.AuthenticationResult(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if !validated {
					t.Fatal("token request validation function wasn't called")
				}
				// silent authentication should succeed for the given tenant
				if ar, err = client.AcquireTokenSilent(ctx, tokenScope, WithSilentAccount(ar.Account), WithTenantID(test.tenant)); err != nil {
					t.Fatal(err)
				} else if ar.AccessToken != "*" {
					t.Fatalf(`unexpected cached token "%s"`, ar.AccessToken)
				}
				// ... but fail for another tenant
				if _, err = client.AcquireTokenSilent(ctx, tokenScope, WithSilentAccount(ar.Account), WithTenantID("not-"+test.tenant)); err == nil {
					t.Fatal("expected an error")
				}
			})
		}
	}
}
