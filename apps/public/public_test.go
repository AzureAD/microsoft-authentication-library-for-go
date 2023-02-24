// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package public

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/fake"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/wstrust"
	"github.com/kylelemons/godebug/pretty"
)

const authorityFmt = "https://%s/%s"

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
	realBrowserOpenURL := browserOpenURL
	defer func() { browserOpenURL = realBrowserOpenURL }()
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

func TestAcquireTokenSilentHomeTenantAliases(t *testing.T) {
	accessToken := "*"
	homeTenant := "home-tenant"
	clientInfo := base64.RawStdEncoding.EncodeToString([]byte(
		fmt.Sprintf(`{"uid":"uid","utid":"%s"}`, homeTenant),
	))
	lmo := "login.microsoftonline.com"
	for _, alias := range []string{"common", "organizations"} {
		mockClient := mock.Client{}
		mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, alias)))
		mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody(accessToken, mock.GetIDToken(homeTenant, fmt.Sprintf(authorityFmt, lmo, homeTenant)), "rt", clientInfo, 3600)))
		mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, homeTenant)))
		client, err := New("client-id", WithAuthority(fmt.Sprintf(authorityFmt, lmo, alias)), WithHTTPClient(&mockClient))
		if err != nil {
			t.Fatal(err)
		}
		// the auth flow isn't important, we just need to populate the cache
		ar, err := client.AcquireTokenByAuthCode(context.Background(), "code", "https://localhost", tokenScope)
		if err != nil {
			t.Fatal(err)
		}
		if ar.AccessToken != accessToken {
			t.Fatalf("expected %q, got %q", accessToken, ar.AccessToken)
		}
		account := ar.Account
		ar, err = client.AcquireTokenSilent(context.Background(), tokenScope, WithSilentAccount(account))
		if err != nil {
			t.Fatal(err)
		}
		if ar.AccessToken != accessToken {
			t.Fatalf("expected %q, got %q", accessToken, ar.AccessToken)
		}
	}
}

func TestAcquireTokenSilentWithTenantID(t *testing.T) {
	tenantA, tenantB := "a", "b"
	lmo := "login.microsoftonline.com"
	mockClient := mock.Client{}
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenantA)))
	client, err := New("client-id", WithAuthority(fmt.Sprintf(authorityFmt, lmo, tenantA)), WithHTTPClient(&mockClient))
	if err != nil {
		t.Fatal(err)
	}
	clientInfo := base64.RawStdEncoding.EncodeToString([]byte(`{"uid":"uid","utid":"utid"}`))
	ctx := context.Background()
	// cache an access token for each tenant. To simplify determining their provenance below, the value of each token is the ID of the tenant that provided it.
	for _, tenant := range []string{tenantA, tenantB} {
		if _, err = client.AcquireTokenSilent(ctx, tokenScope, WithTenantID(tenant)); err == nil {
			t.Fatal("silent auth should fail because the cache is empty")
		}
		mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
		mockClient.AppendResponse(mock.WithBody([]byte(`{"account_type":"Managed","cloud_audience_urn":"urn","cloud_instance_name":"...","domain_name":"..."}`)))
		mockClient.AppendResponse(mock.WithBody(
			mock.GetAccessTokenBody(tenant, mock.GetIDToken(tenant, fmt.Sprintf(authorityFmt, lmo, tenant)), "rt-"+tenant, clientInfo, 3600)),
		)
		ar, err := client.AcquireTokenByUsernamePassword(ctx, tokenScope, "username", "password", WithTenantID(tenant))
		if err != nil {
			t.Fatal(err)
		}
		if ar.AccessToken != tenant {
			t.Fatalf(`unexpected token "%s"`, ar.AccessToken)
		}
	}

	// cache should return the correct access token for each tenant
	var account Account
	accounts, err := client.Accounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// expecting one account for each tenant we authenticated in above
	if len(accounts) == 2 {
		account = accounts[0]
	} else {
		t.Fatalf("expected 2 accounts but got %d", len(accounts))
	}
	for _, test := range []struct {
		desc, expected string
		opts           []AcquireSilentOption
	}{
		// when no tenant is specified the client should return the cached token for its configured authority
		{"no tenant specified", tenantA, []AcquireSilentOption{WithSilentAccount(account)}},

		// when a tenant is specified the client should return the cached token for that tenant
		{"redundant tenant specified", tenantA, []AcquireSilentOption{WithSilentAccount(account), WithTenantID(tenantA)}},
		{"different tenant specified", tenantB, []AcquireSilentOption{WithSilentAccount(account), WithTenantID(tenantB)}},
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

func TestAcquireTokenWithTenantID(t *testing.T) {
	// replacing browserOpenURL with a fake for the duration of this test enables testing AcquireTokenInteractive
	realBrowserOpenURL := browserOpenURL
	defer func() { browserOpenURL = realBrowserOpenURL }()
	browserOpenURL = fakeBrowserOpenURL

	accessToken := "*"
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
		{authority: host + "organizations", tenant: uuid1, expectedAuthority: host + uuid1},
		{authority: host + uuid1, tenant: uuid2, expectedAuthority: host + uuid2},
		{authority: host + uuid1, tenant: "common", expectError: true},
		{authority: host + uuid1, tenant: "organizations", expectError: true},
		{authority: host + "consumers", tenant: uuid1, expectError: true},
	} {
		for _, method := range []string{"authcode", "authcodeURL", "devicecode", "interactive", "password"} {
			t.Run(method, func(t *testing.T) {
				URL := ""
				mockClient := mock.Client{}
				if method == "obo" {
					// TODO: OBO does instance discovery twice before first token request https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/351
					mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, test.tenant)))
				}
				mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, test.tenant)))
				mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, test.tenant)))
				if method == "devicecode" {
					mockClient.AppendResponse(mock.WithBody([]byte(`{"device_code":"...","expires_in":600}`)))
				} else if method == "password" {
					// user realm metadata
					mockClient.AppendResponse(mock.WithBody([]byte(`{"account_type":"Managed","cloud_audience_urn":"urn","cloud_instance_name":"...","domain_name":"..."}`)))
				}
				mockClient.AppendResponse(
					mock.WithBody(mock.GetAccessTokenBody(accessToken, mock.GetIDToken(test.tenant, test.authority), "rt", clientInfo, 3600)),
					mock.WithCallback(func(r *http.Request) { URL = r.URL.String() }),
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
				switch method {
				case "authcode":
					ar, err = client.AcquireTokenByAuthCode(ctx, "auth code", "https://localhost", tokenScope, WithTenantID(test.tenant))
				case "authcodeURL":
					URL, err = client.AuthCodeURL(ctx, "client-id", "https://localhost", tokenScope, WithTenantID(test.tenant))
				case "devicecode":
					dc, err = client.AcquireTokenByDeviceCode(ctx, tokenScope, WithTenantID(test.tenant))
				case "interactive":
					ar, err = client.AcquireTokenInteractive(ctx, tokenScope, WithTenantID(test.tenant))
				case "password":
					ar, err = client.AcquireTokenByUsernamePassword(ctx, tokenScope, "username", "password", WithTenantID(test.tenant))
				default:
					t.Fatalf("test bug: no test for " + method)
				}
				if err != nil {
					if test.expectError {
						return
					}
					t.Fatal(err)
				} else if test.expectError {
					t.Fatal("expected an error")
				}
				if method == "devicecode" {
					if ar, err = dc.AuthenticationResult(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if !strings.HasPrefix(URL, test.expectedAuthority) {
					t.Fatalf(`expected "%s", got "%s"`, test.expectedAuthority, URL)
				}
				if method == "authcodeURL" {
					// didn't acquire a token, no need to test silent auth
					return
				}
				if ar.AccessToken != accessToken {
					t.Fatalf(`unexpected access token "%s"`, ar.AccessToken)
				}
				// silent authentication should succeed for the given tenant because the client has a cached
				// access token, and for a different tenant because the client has a cached refresh token
				if ar, err = client.AcquireTokenSilent(ctx, tokenScope, WithSilentAccount(ar.Account), WithTenantID(test.tenant)); err != nil {
					t.Fatal(err)
				} else if ar.AccessToken != accessToken {
					t.Fatal("cached access token should match the one returned by AcquireToken...")
				}
				otherTenant := "not-" + test.tenant
				mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, otherTenant)))
				mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody(accessToken, mock.GetIDToken(otherTenant, test.authority), "rt", clientInfo, 3600)))
				if _, err = client.AcquireTokenSilent(ctx, tokenScope, WithSilentAccount(ar.Account), WithTenantID("not-"+test.tenant)); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestWithInstanceDiscovery(t *testing.T) {
	// replacing browserOpenURL with a fake for the duration of this test enables testing AcquireTokenInteractive
	realBrowserOpenURL := browserOpenURL
	defer func() { browserOpenURL = realBrowserOpenURL }()
	browserOpenURL = fakeBrowserOpenURL

	accessToken := "*"
	clientInfo := base64.RawStdEncoding.EncodeToString([]byte(`{"uid":"uid","utid":"utid"}`))
	host := "stack.local"
	stackurl := fmt.Sprintf("https://%s/", host)

	for _, tenant := range []string{
		"adfs",
		"98b8267d-e97f-426e-8b3f-7956511fd63f",
	} {
		for _, method := range []string{"authcode", "devicecode", "interactive", "password"} {
			t.Run(method, func(t *testing.T) {
				authority := stackurl + tenant
				mockClient := mock.Client{}
				mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(host, tenant)))
				if method == "devicecode" {
					mockClient.AppendResponse(mock.WithBody([]byte(`{"device_code":"...","expires_in":600}`)))
				} else if method == "password" && tenant != "adfs" {
					// user realm metadata, which is not requested when AuthorityType is ADFS
					mockClient.AppendResponse(mock.WithBody([]byte(`{"account_type":"Managed","cloud_audience_urn":"urn","cloud_instance_name":"...","domain_name":"..."}`)))
				}
				mockClient.AppendResponse(
					mock.WithBody(mock.GetAccessTokenBody(accessToken, mock.GetIDToken(tenant, authority), "rt", clientInfo, 3600)),
				)
				client, err := New("client-id", WithAuthority(authority), WithHTTPClient(&mockClient), WithInstanceDiscovery(false))
				if err != nil {
					t.Fatal(err)
				}
				ctx := context.Background()
				if _, err = client.AcquireTokenSilent(ctx, tokenScope); err == nil {
					t.Fatal("silent auth should fail because the cache is empty")
				}

				var ar AuthResult
				var dc DeviceCode
				switch method {
				case "authcode":
					ar, err = client.AcquireTokenByAuthCode(ctx, "auth code", "https://localhost", tokenScope)
				case "devicecode":
					dc, err = client.AcquireTokenByDeviceCode(ctx, tokenScope)
				case "interactive":
					ar, err = client.AcquireTokenInteractive(ctx, tokenScope)
				case "password":
					ar, err = client.AcquireTokenByUsernamePassword(ctx, tokenScope, "username", "password")
				default:
					t.Fatal("test bug: no test for " + method)
				}
				if err != nil {
					t.Fatal(err)
				}
				if method == "devicecode" {
					if ar, err = dc.AuthenticationResult(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if ar.AccessToken != accessToken {
					t.Fatalf(`unexpected access token "%s"`, ar.AccessToken)
				}

				if ar, err = client.AcquireTokenSilent(ctx, tokenScope, WithSilentAccount(ar.Account)); err != nil {
					t.Fatal(err)
				} else if ar.AccessToken != accessToken {
					t.Fatal("cached access token should match the one returned by AcquireToken...")
				}
			})
		}
	}
}

// testCache is a simple in-memory cache.ExportReplace implementation
type testCache map[string][]byte

func (c testCache) Export(ctx context.Context, m cache.Marshaler, h cache.ExportHints) error {
	v, err := m.Marshal()
	if err == nil {
		c[h.PartitionKey] = v
	}
	return err
}

func (c testCache) Replace(ctx context.Context, u cache.Unmarshaler, h cache.ReplaceHints) error {
	if v, has := c[h.PartitionKey]; has {
		return u.Unmarshal(v)
	}
	return nil
}

func TestWithCache(t *testing.T) {
	cache := make(testCache)
	accessToken, refreshToken := "*", "rt"
	clientInfo := base64.RawStdEncoding.EncodeToString([]byte(`{"uid":"uid","utid":"utid"}`))
	lmo := "login.microsoftonline.com"
	tenantA, tenantB := "a", "b"
	authorityA, authorityB := fmt.Sprintf(authorityFmt, lmo, tenantA), fmt.Sprintf(authorityFmt, lmo, tenantB)
	mockClient := mock.Client{}
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenantA)))
	mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody(accessToken, mock.GetIDToken(tenantA, authorityA), refreshToken, clientInfo, 3600)))

	client, err := New("client-id", WithAuthority(authorityA), WithCache(&cache), WithHTTPClient(&mockClient))
	if err != nil {
		t.Fatal(err)
	}
	// The particular flow isn't important, we just need to populate the cache. Auth code is the simplest for this test
	ar, err := client.AcquireTokenByAuthCode(context.Background(), "code", "https://localhost", tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if ar.AccessToken != accessToken {
		t.Fatalf(`unexpected access token "%s"`, ar.AccessToken)
	}
	account := ar.Account
	if actual := account.Realm; actual != tenantA {
		t.Fatalf(`unexpected realm "%s"`, actual)
	}

	// a client configured for a different tenant should be able to authenticate silently with the shared cache's data
	client, err = New("client-id", WithAuthority(authorityB), WithCache(&cache), WithHTTPClient(&mockClient))
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := client.Accounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if actual := len(accounts); actual != 1 {
		t.Fatalf("expected 1 account but cache contains %d", actual)
	}
	if diff := pretty.Compare(account, accounts[0]); diff != "" {
		t.Fatal(diff)
	}

	// this should work because the cache contains an access token from tenantA
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenantA)))
	ar, err = client.AcquireTokenSilent(context.Background(), tokenScope, WithSilentAccount(account), WithTenantID(tenantA))
	if err != nil {
		t.Fatal(err)
	}
	if ar.AccessToken != accessToken {
		t.Fatalf(`unexpected access token "%s"`, ar.AccessToken)
	}

	// this should work because the cache contains a refresh token for the user
	accessToken2 := accessToken + "2"
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenantB)))
	mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody(accessToken2, mock.GetIDToken(tenantB, authorityB), refreshToken, clientInfo, 3600)))
	ar, err = client.AcquireTokenSilent(context.Background(), tokenScope, WithSilentAccount(account))
	if err != nil {
		t.Fatal(err)
	}
	if ar.AccessToken != accessToken2 {
		t.Fatalf(`unexpected access token "%s"`, ar.AccessToken)
	}
}

func TestWithClaims(t *testing.T) {
	// replacing browserOpenURL with a fake for the duration of this test enables testing AcquireTokenInteractive
	realBrowserOpenURL := browserOpenURL
	defer func() { browserOpenURL = realBrowserOpenURL }()
	browserOpenURL = fakeBrowserOpenURL

	clientInfo := base64.RawStdEncoding.EncodeToString([]byte(`{"uid":"uid","utid":"utid"}`))
	lmo, tenant := "login.microsoftonline.com", "tenant"
	authority := fmt.Sprintf(authorityFmt, lmo, tenant)
	accessToken, idToken, refreshToken := "at", mock.GetIDToken(tenant, lmo), "rt"
	for _, test := range []struct {
		capabilities     []string
		claims, expected string
	}{
		{},
		{
			capabilities: []string{"cp1"},
			expected:     `{"access_token":{"xms_cc":{"values":["cp1"]}}}`,
		},
		{
			claims:   `{"id_token":{"auth_time":{"essential":true}}}`,
			expected: `{"id_token":{"auth_time":{"essential":true}}}`,
		},
		{
			capabilities: []string{"cp1", "cp2"},
			claims:       `{"access_token":{"nbf":{"essential":true, "value":"42"}}}`,
			expected:     `{"access_token":{"nbf":{"essential":true, "value":"42"}, "xms_cc":{"values":["cp1","cp2"]}}}`,
		},
	} {
		var expected map[string]any
		if err := json.Unmarshal([]byte(test.expected), &expected); err != nil && test.expected != "" {
			t.Fatal("test bug: the expected result must be JSON or an empty string")
		}
		// validate determines whether a request's query or form values contain the expected claims
		validate := func(t *testing.T, v url.Values) {
			if test.expected == "" {
				if v.Has("claims") {
					t.Fatal("claims shouldn't be set")
				}
				return
			}
			claims, ok := v["claims"]
			if !ok {
				t.Fatal("claims should be set")
			}
			if len(claims) != 1 {
				t.Fatalf("expected exactly 1 claims value, got %d", len(claims))
			}
			var actual map[string]any
			if err := json.Unmarshal([]byte(claims[0]), &actual); err != nil {
				t.Fatal(err)
			}
			if diff := pretty.Compare(expected, actual); diff != "" {
				t.Fatal(diff)
			}
		}
		for _, method := range []string{"authcode", "authcodeURL", "devicecode", "interactive", "password", "passwordFederated"} {
			t.Run(method, func(t *testing.T) {
				mockClient := mock.Client{}
				if method == "obo" {
					// TODO: OBO does instance discovery twice before first token request https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/351
					mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenant)))
				}
				mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenant)))
				mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
				switch method {
				case "devicecode":
					mockClient.AppendResponse(mock.WithBody([]byte(`{"device_code":".","expires_in":600}`)))
				case "password":
					mockClient.AppendResponse(mock.WithBody([]byte(`{"account_type":"Managed","cloud_audience_urn":".","cloud_instance_name":".","domain_name":"."}`)))
				case "passwordFederated":
					mockClient.AppendResponse(mock.WithBody([]byte(`{"account_type":"Federated","cloud_audience_urn":".","cloud_instance_name":".","domain_name":".","federation_protocol":".","federation_metadata_url":"."}`)))
				}
				mockClient.AppendResponse(
					mock.WithBody(mock.GetAccessTokenBody(accessToken, idToken, refreshToken, clientInfo, 3600)),
					mock.WithCallback(func(r *http.Request) {
						if err := r.ParseForm(); err != nil {
							t.Fatal(err)
						}
						validate(t, r.Form)
					}),
				)
				client, err := New("client-id", WithAuthority(authority), WithClientCapabilities(test.capabilities), WithHTTPClient(&mockClient))
				if err != nil {
					t.Fatal(err)
				}
				if _, err = client.AcquireTokenSilent(context.Background(), tokenScope); err == nil {
					t.Fatal("silent authentication should fail because the cache is empty")
				}
				ctx := context.Background()
				var ar AuthResult
				var dc DeviceCode
				switch method {
				case "authcode":
					ar, err = client.AcquireTokenByAuthCode(ctx, "auth code", "https://localhost", tokenScope, WithClaims(test.claims))
				case "authcodeURL":
					u := ""
					if u, err = client.AuthCodeURL(ctx, "client-id", "https://localhost", tokenScope, WithClaims(test.claims)); err == nil {
						var parsed *url.URL
						if parsed, err = url.Parse(u); err == nil {
							validate(t, parsed.Query())
							return // didn't acquire a token, no need for further validation
						}
					}
				case "devicecode":
					dc, err = client.AcquireTokenByDeviceCode(ctx, tokenScope, WithClaims(test.claims))
				case "interactive":
					ar, err = client.AcquireTokenInteractive(ctx, tokenScope, WithClaims(test.claims))
				case "password":
					ar, err = client.AcquireTokenByUsernamePassword(ctx, tokenScope, "username", "password", WithClaims(test.claims))
				case "passwordFederated":
					client.base.Token.WSTrust = fake.WSTrust{SamlTokenInfo: wstrust.SamlTokenInfo{AssertionType: "urn:ietf:params:oauth:grant-type:saml1_1-bearer"}}
					ar, err = client.AcquireTokenByUsernamePassword(ctx, tokenScope, "username", "password", WithClaims(test.claims))
				default:
					t.Fatalf("test bug: no test for " + method)
				}
				if method == "devicecode" && err == nil {
					// complete the device code flow
					ar, err = dc.AuthenticationResult(ctx)
				}
				if err != nil {
					t.Fatal(err)
				}
				if ar.AccessToken != accessToken {
					t.Fatalf(`unexpected access token "%s"`, ar.AccessToken)
				}
				// silent auth should now succeed because the client has an access token cached
				ar, err = client.AcquireTokenSilent(ctx, tokenScope, WithSilentAccount(ar.Account))
				if err != nil {
					t.Fatal(err)
				}
				if ar.AccessToken != accessToken {
					t.Fatalf(`unexpected access token "%s"`, ar.AccessToken)
				}
				if test.claims != "" {
					// when given claims, AcquireTokenSilent should request a new access token instead of returning the cached one
					newToken := "new-access-token"
					mockClient.AppendResponse(
						mock.WithBody(mock.GetAccessTokenBody(newToken, idToken, "", clientInfo, 3600)),
						mock.WithCallback(func(r *http.Request) {
							if err := r.ParseForm(); err != nil {
								t.Fatal(err)
							}
							// all token requests should include any specified claims
							validate(t, r.Form)
							if actual := r.Form.Get("refresh_token"); actual != refreshToken {
								t.Fatalf(`unexpected refresh token "%s"`, actual)
							}
						}),
					)
					ar, err = client.AcquireTokenSilent(ctx, tokenScope, WithClaims(test.claims), WithSilentAccount(ar.Account))
					if err != nil {
						t.Fatal(err)
					}
					if actual := ar.AccessToken; actual != newToken {
						t.Fatalf("Expected %s, got %s. Client should have redeemed its cached refresh token for a new access token.", newToken, actual)
					}
				}
			})
		}
	}
}

func TestWithPortAuthority(t *testing.T) {
	accessToken := "*"
	sl := "stack.local"
	port := ":3001"
	host := sl + port
	tenant := "00000000-0000-0000-0000-000000000000"
	authority := fmt.Sprintf("https://%s%s/%s", sl, port, tenant)
	idToken, refreshToken, URL := "", "", ""
	mockClient := mock.Client{}
	//2 calls to instance discovery are made because Host is not trusted
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(host, tenant)))
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(host, tenant)))
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(host, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody(accessToken, idToken, refreshToken, "", 3600)),
		mock.WithCallback(func(r *http.Request) { URL = r.URL.String() }),
	)
	client, err := New("client-id", WithAuthority(authority), WithHTTPClient(&mockClient))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = client.AcquireTokenSilent(ctx, tokenScope); err == nil {
		t.Fatal("silent auth should fail because the cache is empty")
	}
	var ar AuthResult
	ar, err = client.AcquireTokenByAuthCode(ctx, "auth code", "https://localhost", tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(URL, authority) {
		t.Fatalf(`expected "%s", got "%s"`, authority, URL)
	}
	if ar.AccessToken != accessToken {
		t.Fatalf(`unexpected access token "%s"`, ar.AccessToken)
	}
	if ar, err = client.AcquireTokenSilent(ctx, tokenScope); err != nil {
		t.Fatal(err)
	}
	if ar.AccessToken != accessToken {
		t.Fatal("cached access token should match the one returned by AcquireToken...")
	}
}

func TestWithLoginHint(t *testing.T) {
	realBrowserOpenURL := browserOpenURL
	defer func() { browserOpenURL = realBrowserOpenURL }()
	upn := "user@localhost"
	client, err := New("client-id")
	if err != nil {
		t.Fatal(err)
	}
	client.base.Token.AccessTokens = &fake.AccessTokens{}
	client.base.Token.Authority = &fake.Authority{}
	client.base.Token.Resolver = &fake.ResolveEndpoints{}
	for _, expectHint := range []bool{true, false} {
		t.Run(fmt.Sprint(expectHint), func(t *testing.T) {
			// replace the browser launching function with a fake that validates login_hint is set as expected
			called := false
			validate := func(v url.Values) error {
				if !v.Has("login_hint") {
					if !expectHint {
						return nil
					}
					return errors.New("expected a login hint")
				} else if !expectHint {
					return errors.New("expected no login hint")
				}
				if actual := v["login_hint"]; len(actual) != 1 || actual[0] != upn {
					err = fmt.Errorf(`unexpected login_hint "%v"`, actual)
				}
				return err
			}
			browserOpenURL = func(authURL string) error {
				called = true
				parsed, err := url.Parse(authURL)
				if err != nil {
					return err
				}
				query, err := url.ParseQuery(parsed.RawQuery)
				if err != nil {
					return err
				}
				if err = validate(query); err != nil {
					t.Fatal(err)
					return err
				}
				// this helper validates the other params and completes the redirect
				return fakeBrowserOpenURL(authURL)
			}
			acquireOpts := []AcquireInteractiveOption{}
			urlOpts := []AuthCodeURLOption{}
			if expectHint {
				acquireOpts = append(acquireOpts, WithLoginHint(upn))
				urlOpts = append(urlOpts, WithLoginHint(upn))
			}
			_, err = client.AcquireTokenInteractive(context.Background(), tokenScope, acquireOpts...)
			if err != nil {
				t.Fatal(err)
			}
			if !called {
				t.Fatal("browserOpenURL wasn't called")
			}
			u, err := client.AuthCodeURL(context.Background(), "id", "https://localhost", tokenScope, urlOpts...)
			if err == nil {
				var parsed *url.URL
				parsed, err = url.Parse(u)
				if err == nil {
					err = validate(parsed.Query())
				}
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWithDomainHint(t *testing.T) {
	realBrowserOpenURL := browserOpenURL
	defer func() { browserOpenURL = realBrowserOpenURL }()
	domain := "contoso.com"
	client, err := New("client-id")
	if err != nil {
		t.Fatal(err)
	}
	client.base.Token.AccessTokens = &fake.AccessTokens{}
	client.base.Token.Authority = &fake.Authority{}
	client.base.Token.Resolver = &fake.ResolveEndpoints{}
	for _, expectHint := range []bool{true, false} {
		t.Run(fmt.Sprint(expectHint), func(t *testing.T) {
			// replace the browser launching function with a fake that validates domain_hint is set as expected
			called := false
			validate := func(v url.Values) error {
				if !v.Has("domain_hint") {
					if !expectHint {
						return nil
					}
					return errors.New("expected a domain hint")
				} else if !expectHint {
					return errors.New("expected no domain hint")
				}
				if actual := v["domain_hint"]; len(actual) != 1 || actual[0] != domain {
					err = fmt.Errorf(`unexpected domain_hint "%v"`, actual)
				}
				return err
			}
			browserOpenURL = func(authURL string) error {
				called = true
				parsed, err := url.Parse(authURL)
				if err != nil {
					return err
				}
				query, err := url.ParseQuery(parsed.RawQuery)
				if err != nil {
					return err
				}
				if err = validate(query); err != nil {
					t.Fatal(err)
					return err
				}
				// this helper validates the other params and completes the redirect
				return fakeBrowserOpenURL(authURL)
			}
			var acquireOpts []AcquireInteractiveOption
			var urlOpts []AuthCodeURLOption
			if expectHint {
				acquireOpts = append(acquireOpts, WithDomainHint(domain))
				urlOpts = append(urlOpts, WithDomainHint(domain))
			}
			_, err = client.AcquireTokenInteractive(context.Background(), tokenScope, acquireOpts...)
			if err != nil {
				t.Fatal(err)
			}
			if !called {
				t.Fatal("browserOpenURL wasn't called")
			}
			u, err := client.AuthCodeURL(context.Background(), "id", "https://localhost", tokenScope, urlOpts...)
			if err == nil {
				var parsed *url.URL
				parsed, err = url.Parse(u)
				if err == nil {
					err = validate(parsed.Query())
				}
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
