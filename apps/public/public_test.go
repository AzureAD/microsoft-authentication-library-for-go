// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package public

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/fake"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

var tokenScope = []string{"the_scope"}

func fakeClient(tk accesstokens.TokenResponse, options ...Option) (Client, error) {
	options = append(options, WithAuthority("https://localhost/tenant"))
	client, err := New("client-id", options...)
	if err != nil {
		return Client{}, err
	}
	client.base.Token.AccessTokens = &fake.AccessTokens{
		AccessToken: tk,
		DeviceCode: accesstokens.NewDeviceCodeResult(
			"user code",
			"device code",
			"https://localhost",
			time.Now().Add(time.Minute),
			1,
			"message",
			"client-id",
			tokenScope,
		),
		Result: []error{nil},
	}
	client.base.Token.Authority = &fake.Authority{
		InstanceResp: authority.InstanceDiscoveryResponse{
			TenantDiscoveryEndpoint: "https://localhost/fake/discovery/endpoint",
			Metadata: []authority.InstanceDiscoveryMetadata{
				{
					PreferredNetwork: "localhost",
					PreferredCache:   "localhost_cache",
					Aliases:          []string{"localhost"},
				},
			},
			AdditionalFields: map[string]interface{}{"api-version": "2020-02-02"},
		},
		Realm: authority.UserRealm{AccountType: authority.Managed},
	}
	client.base.Token.Resolver = &fake.ResolveEndpoints{
		Endpoints: authority.NewEndpoints(
			"https://localhost/tenant/auth",
			"https://localhost/tenant/token",
			"https://localhost/tenant/jwt",
			"localhost",
		),
	}
	client.base.Token.WSTrust = &fake.WSTrust{}
	return client, nil
}

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

func TestAcquireTokenWithTenantID(t *testing.T) {
	uuid1 := "00000000-0000-0000-0000-000000000000"
	uuid2 := strings.ReplaceAll(uuid1, "0", "1")
	host := "https://localhost/"
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
		for _, flow := range []string{"authcode", "devicecode", "password"} {
			t.Run(flow, func(t *testing.T) {
				client, err := fakeClient(accesstokens.TokenResponse{
					AccessToken:   "***",
					ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(time.Hour)},
					GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
					RefreshToken:  "refresh-token",
				}, WithAuthority(test.authority))
				if err != nil {
					t.Fatal(err)
				}

				validated := false
				client.base.Token.AccessTokens.(*fake.AccessTokens).ValidateAuthParams = func(p authority.AuthParams) {
					if validated {
						// e.g. AcquireTokenSilent should return a cached token
						t.Fatal("unexpected second authentication")
					}
					validated = true
					if actual := strings.TrimSuffix(p.AuthorityInfo.CanonicalAuthorityURI, "/"); actual != test.expectedAuthority {
						t.Fatalf(`unexpected authority "%s"`, actual)
					}
				}

				var dc DeviceCode
				ctx := context.Background()
				switch flow {
				case "authcode":
					_, err = client.AcquireTokenByAuthCode(ctx, "auth code", "https://localhost", tokenScope, WithTenantID(test.tenant))
				case "devicecode":
					dc, err = client.AcquireTokenByDeviceCode(ctx, tokenScope, WithTenantID(test.tenant))
				case "password":
					_, err = client.AcquireTokenByUsernamePassword(ctx, tokenScope, "username", "password", WithTenantID(test.tenant))
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
					if _, err = dc.AuthenticationResult(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if !validated {
					t.Fatal("AuthParams validation function wasn't called")
				}
				if _, err = client.AcquireTokenSilent(ctx, tokenScope, WithTenantID(test.tenant)); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
