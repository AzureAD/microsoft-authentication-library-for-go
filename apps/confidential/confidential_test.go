// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kylelemons/godebug/pretty"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/exported"
	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/fake"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

// errorClient is an HTTP client for tests that should fail when confidential.Client sends a request
type errorClient struct{}
type contextKey struct{}

func (*errorClient) Do(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("expected no requests but received one for %s", req.URL.String())
}

func (*errorClient) CloseIdleConnections() {}

func TestCertFromPEM(t *testing.T) {
	f, err := os.Open(filepath.Clean("../testdata/test-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pemData, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	certs, key, err := CertFromPEM(pemData, "")
	if err != nil {
		t.Fatalf("TestCertFromPEM: got err == %s, want err == nil", err)
	}
	if len(certs) != 1 {
		t.Fatalf("TestCertFromPEM: got %d certs, want 1 cert", len(certs))
	}
	if key == nil {
		t.Fatalf("TestCertFromPEM: got nil key, want key != nil")
	}
}

const (
	authorityFmt      = "https://%s/%s"
	fakeAuthority     = "https://fake_authority/fake_tenant"
	fakeClientID      = "fake_client_id"
	fakeSecret        = "fake_secret"
	fakeTokenEndpoint = "https://fake_authority/fake_tenant/token"
	localhost         = "http://localhost"
	refresh           = "fake_refresh"
	token             = "fake_token"
)

var tokenScope = []string{"the_scope"}

func fakeClient(tk accesstokens.TokenResponse, credential Credential, fakeAuthority string, options ...Option) (Client, error) {
	client, err := New(fakeAuthority, fakeClientID, credential, options...)
	if err != nil {
		return Client{}, err
	}
	client.base.Token.AccessTokens = &fake.AccessTokens{
		AccessToken: tk,
	}
	client.base.Token.Authority = &fake.Authority{
		InstanceResp: authority.InstanceDiscoveryResponse{
			TenantDiscoveryEndpoint: fakeAuthority + "/discovery/endpoint",
			Metadata: []authority.InstanceDiscoveryMetadata{
				{
					PreferredNetwork: "fake_authority",
					PreferredCache:   "fake_cache",
					Aliases: []string{
						"fake_authority",
						"fake_auth",
						"fk_au",
					},
				},
			},
			AdditionalFields: map[string]interface{}{
				"api-version": "2020-02-02",
			},
		},
	}
	client.base.Token.Resolver = &fake.ResolveEndpoints{
		Endpoints: authority.NewEndpoints(
			fakeAuthority+"/auth",
			fakeAuthority+"/token",
			fakeAuthority+"/jwt",
			fakeAuthority,
		),
	}
	client.base.Token.WSTrust = &fake.WSTrust{}
	return client, nil
}

func TestAcquireTokenByCredential(t *testing.T) {
	tests := []struct {
		desc string
		cred string
	}{
		{
			desc: "Secret",
			cred: "fake_secret",
		},
		{
			desc: "Signed Assertion",
			cred: "fake_assertion",
		},
	}

	for _, test := range tests {
		cred, err := NewCredFromSecret(test.cred)
		if err != nil {
			t.Fatal(err)
		}
		client, err := fakeClient(accesstokens.TokenResponse{
			AccessToken:   token,
			RefreshOn:     internalTime.DurationTime{T: time.Now().Add(6 * time.Hour)},
			ExpiresOn:     time.Now().Add(12 * time.Hour),
			ExtExpiresOn:  internalTime.DurationTime{T: time.Now().Add(12 * time.Hour)},
			GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
			TokenType:     "Bearer",
		}, cred, fakeAuthority)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.AcquireTokenSilent(context.Background(), tokenScope)
		// first attempt should fail
		if err == nil {
			t.Errorf("TestAcquireTokenByCredential(%s): unexpected nil error from AcquireTokenSilent", test.desc)
		}
		tk, err := client.AcquireTokenByCredential(context.Background(), tokenScope)
		if err != nil {
			t.Errorf("TestAcquireTokenByCredential(%s): got err == %s, want err == nil", test.desc, err)
		}
		if tk.AccessToken != token {
			t.Errorf("TestAcquireTokenByCredential(%s): unexpected access token %s", test.desc, tk.AccessToken)
		}
		// second attempt should return the cached token
		tk, err = client.AcquireTokenSilent(context.Background(), tokenScope)
		if err != nil {
			t.Errorf("TestAcquireTokenByCredential(%s): got err == %s, want err == nil", test.desc, err)
		}
		if tk.AccessToken != token {
			t.Errorf("TestAcquireTokenByCredential(%s): unexpected access token %s", test.desc, tk.AccessToken)
		}
	}
}

func TestRegionAutoEnable_EmptyRegion_EnvRegion(t *testing.T) {
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}

	envRegion := "envRegion"
	err = os.Setenv("MSAL_FORCE_REGION", envRegion)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv("MSAL_FORCE_REGION")

	lmo := "login.microsoftonline.com"
	tenant := "tenant"
	mockClient := mock.NewClient()

	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred, WithHTTPClient(mockClient))
	if err != nil {
		t.Fatal(err)
	}

	if client.base.AuthParams.AuthorityInfo.Region != envRegion {
		t.Fatalf("wanted %q, got %q", envRegion, client.base.AuthParams.AuthorityInfo.Region)
	}
}

func TestRegionAutoEnable_SpecifiedEmptyRegion_EnvRegion(t *testing.T) {
	tests := []struct {
		name         string
		envRegion    string
		region       string
		resultRegion string
	}{
		{
			name:         "Region is empty, envRegion is set",
			envRegion:    "region",
			region:       "",
			resultRegion: "region",
		},
		{
			name:         "Region is set, envRegion is set",
			envRegion:    "region",
			region:       "setRegion",
			resultRegion: "setRegion",
		},
		{
			name:         "Region is set, envRegion is empty",
			envRegion:    "",
			region:       "setRegion",
			resultRegion: "setRegion",
		},
		{
			name:         "Disable region is set, envRegion is set",
			envRegion:    "region",
			region:       "DisableMsalForceRegion",
			resultRegion: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cred, err := NewCredFromSecret(fakeSecret)
			if err != nil {
				t.Fatal(err)
			}
			if test.envRegion != "" {
				t.Setenv("MSAL_FORCE_REGION", test.envRegion)
			}
			lmo := "login.microsoftonline.com"
			tenant := "tenant"
			mockClient := mock.NewClient()

			client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred, WithHTTPClient(mockClient), WithAzureRegion(test.region))
			if err != nil {
				t.Fatal(err)
			}

			if test.resultRegion == "DisableMsalForceRegion" {
				if client.base.AuthParams.AuthorityInfo.Region != "" {
					t.Fatalf("wanted %q, got %q", test.resultRegion, client.base.AuthParams.AuthorityInfo.Region)
				}
			} else if client.base.AuthParams.AuthorityInfo.Region != test.resultRegion {
				t.Fatalf("wanted %q, got %q", test.resultRegion, client.base.AuthParams.AuthorityInfo.Region)
			}
		})
	}
}

func TestAcquireTokenOnBehalfOf(t *testing.T) {
	// this test is an offline version of TestOnBehalfOf in integration_test.go
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	lmo := "login.microsoftonline.com"
	tenant := "tenant"
	assertion := "assertion"
	mockClient := mock.NewClient()
	// TODO: OBO does instance discovery twice before first token request https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/351
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody(token, "", "rt", "", 86400, 43200)))

	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred, WithHTTPClient(mockClient))
	if err != nil {
		t.Fatal(err)
	}
	tk, err := client.AcquireTokenOnBehalfOf(context.Background(), assertion, tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if tk.AccessToken != token {
		t.Fatalf("wanted %q, got %q", token, tk.AccessToken)
	}
	// should return the cached access token
	tk, err = client.AcquireTokenOnBehalfOf(context.Background(), assertion, tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if tk.AccessToken != token {
		t.Fatalf("wanted %q, got %q", token, tk.AccessToken)
	}
	// new assertion should trigger new token request
	token2 := token + "2"
	mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody(token2, "", "rt", "", 86400, 43200)))
	tk, err = client.AcquireTokenOnBehalfOf(context.Background(), assertion+"2", tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if tk.AccessToken != token2 {
		t.Fatal("expected a new token")
	}
}

func TestAcquireTokenByAssertionCallback(t *testing.T) {
	calls := 0
	key := contextKey{}
	ctx := context.WithValue(context.Background(), key, true)
	getAssertion := func(c context.Context, o AssertionRequestOptions) (string, error) {
		if v := c.Value(key); v == nil || !v.(bool) {
			t.Fatal("callback received unexpected context")
		}
		if o.ClientID != fakeClientID {
			t.Fatalf(`unexpected client ID "%s"`, o.ClientID)
		}
		if o.TokenEndpoint != fakeTokenEndpoint {
			t.Fatalf(`unexpected token endpoint "%s"`, o.TokenEndpoint)
		}
		calls++
		if calls < 4 {
			return "assertion", nil
		}
		return "", errors.New("expected error")
	}
	cred := NewCredFromAssertionCallback(getAssertion)
	client, err := fakeClient(accesstokens.TokenResponse{}, cred, fakeAuthority)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if calls != i {
			t.Fatalf("expected %d calls, got %d", i, calls)
		}
		_, err = client.AcquireTokenByCredential(ctx, tokenScope)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = client.AcquireTokenByCredential(ctx, tokenScope)
	if err == nil || err.Error() != "expected error" {
		t.Fatalf("expected an error from the callback, got %v", err)
	}
}

func TestAcquireTokenByAuthCode(t *testing.T) {
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	for _, params := range []struct {
		upn, preferredUsername, utid string
	}{
		{"", "fakeuser@fakeplace.fake", "fake"},
		{"fakeuser@fakeplace.fake", "", ""},
	} {
		t.Run("", func(t *testing.T) {
			tr := accesstokens.TokenResponse{
				AccessToken:   token,
				RefreshToken:  refresh,
				ExpiresOn:     time.Now().Add(1 * time.Hour),
				ExtExpiresOn:  internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
				GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
				IDToken: accesstokens.IDToken{
					PreferredUsername: params.preferredUsername,
					UPN:               params.upn,
					Name:              "fake person",
					Oid:               "123-456",
					TenantID:          "fake",
					Subject:           "nothing",
					Issuer:            fakeAuthority,
					Audience:          "abc-123",
					ExpirationTime:    time.Now().Add(time.Hour).Unix(),
					IssuedAt:          time.Now().Add(-5 * time.Minute).Unix(),
					NotBefore:         time.Now().Add(-5 * time.Minute).Unix(),
					// NOTE: this is an invalid JWT however this doesn't cause a failure.
					// it simply falls back to calling Token.Refresh() which will obviously succeed.
					RawToken: "fake.raw.token",
				},
				ClientInfo: accesstokens.ClientInfo{
					UID:  "123-456",
					UTID: params.utid,
				},
			}

			client, err := fakeClient(tr, cred, fakeAuthority)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.AcquireTokenSilent(context.Background(), tokenScope)
			// first attempt should fail
			if err == nil {
				t.Fatal("unexpected nil error from AcquireTokenSilent")
			}
			tk, err := client.AcquireTokenByAuthCode(context.Background(), "fake_auth_code", "fake_redirect_uri", tokenScope)
			if err != nil {
				t.Fatal(err)
			}
			if tk.AccessToken != token {
				t.Fatalf("unexpected access token %s", tk.AccessToken)
			}
			account, err := client.Account(context.Background(), tk.Account.HomeAccountID)
			if err != nil {
				t.Fatal(err)
			}
			if params.utid == "" {
				if actual := account.HomeAccountID; actual != "123-456.123-456" {
					t.Fatalf("expected %q, got %q", "123-456.123-456", actual)
				}
			} else {
				if actual := account.HomeAccountID; actual != "123-456.fake" {
					t.Fatalf("expected %q, got %q", "123-456.fake", actual)
				}
			}
			if account.PreferredUsername != "fakeuser@fakeplace.fake" {
				t.Fatal("Unexpected Account.PreferredUsername")
			}
			// second attempt should return the cached token
			tk, err = client.AcquireTokenSilent(context.Background(), tokenScope, WithSilentAccount(account))
			if err != nil {
				t.Fatal(err)
			}
			if tk.AccessToken != token {
				t.Fatalf("unexpected access token %s", tk.AccessToken)
			}
		})
	}
}

func TestInvalidJsonErrFromResponse(t *testing.T) {
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "A"
	lmo := "login.microsoftonline.com"
	mockClient := mock.NewClient()

	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenant)))
	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred, WithHTTPClient(mockClient))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// cache an access token for each tenant. To simplify determining their provenance below, the value of each token is the ID of the tenant that provided it.
	if _, err = client.AcquireTokenSilent(ctx, tokenScope, WithTenantID(tenant)); err == nil {
		t.Fatal("silent auth should fail because the cache is empty")
	}
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	body := fmt.Sprintf(
		`{"access_token": "%s","expires_in": %d,"expires_on": %d,"token_type": "Bearer"`,
		tenant, 3600, time.Now().Add(time.Duration(3600)*time.Second).Unix(),
	)
	mockClient.AppendResponse(mock.WithBody([]byte(body)))
	_, err = client.AcquireTokenByCredential(ctx, tokenScope, WithTenantID(tenant))
	if err == nil {
		t.Fatal("should have failed with InvalidJsonErr Response")
	}
	var ie errors.InvalidJsonErr
	if !errors.As(err, &ie) {
		t.Fatal("should have revieved a InvalidJsonErr, but got", err)
	}
}

func TestAcquireTokenSilentTenants(t *testing.T) {
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	tenants := []string{"a", "b"}
	lmo := "login.microsoftonline.com"
	mockClient := mock.NewClient()

	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenants[0])))
	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenants[0]), fakeClientID, cred, WithHTTPClient(mockClient))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// cache an access token for each tenant. To simplify determining their provenance below, the value of each token is the ID of the tenant that provided it.
	for _, tenant := range tenants {
		if _, err = client.AcquireTokenSilent(ctx, tokenScope, WithTenantID(tenant)); err == nil {
			t.Fatal("silent auth should fail because the cache is empty")
		}
		mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
		mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody(tenant, "", "", "", 3600, 0)))
		if _, err := client.AcquireTokenByCredential(ctx, tokenScope, WithTenantID(tenant)); err != nil {
			t.Fatal(err)
		}
	}
	// cache should return the correct access token for each tenant
	for _, tenant := range tenants {
		ar, err := client.AcquireTokenSilent(ctx, tokenScope, WithTenantID(tenant))
		if err != nil {
			t.Fatal(err)
		}
		if ar.AccessToken != tenant {
			t.Fatalf(`expected "%s", got "%s"`, tenant, ar.AccessToken)
		}
	}
}

func TestADFSTokenCaching(t *testing.T) {
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New("https://fake_authority/adfs", "clientID", cred)
	if err != nil {
		t.Fatal(err)
	}
	fakeAT := fake.AccessTokens{
		AccessToken: accesstokens.TokenResponse{
			AccessToken:   "at1",
			RefreshToken:  "rt",
			TokenType:     "bearer",
			ExpiresOn:     time.Now().Add(time.Hour),
			ExtExpiresOn:  internalTime.DurationTime{T: time.Now().Add(time.Hour)},
			GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
			IDToken: accesstokens.IDToken{
				ExpirationTime: time.Now().Add(time.Hour).Unix(),
				Name:           "A",
				RawToken:       "x.e30",
				Subject:        "A",
				TenantID:       "tenant",
				UPN:            "A",
			},
		},
	}
	client.base.Token.AccessTokens = &fakeAT
	client.base.Token.Authority = &fake.Authority{
		InstanceResp: authority.InstanceDiscoveryResponse{
			Metadata: []authority.InstanceDiscoveryMetadata{
				{Aliases: []string{"fake_authority"}},
			},
		},
	}
	client.base.Token.Resolver = &fake.ResolveEndpoints{}
	ctx := context.Background()
	ar1, err := client.AcquireTokenByAuthCode(ctx, "code", "http://localhost", tokenScope)
	if err != nil {
		t.Fatal(err)
	}

	// simulate authenticating a different user
	fakeAT.AccessToken.AccessToken = "at2"
	fakeAT.AccessToken.TokenType = "bearer"
	fakeAT.AccessToken.IDToken.Name = "B"
	fakeAT.AccessToken.IDToken.PreferredUsername = "B"
	fakeAT.AccessToken.IDToken.Subject = "B"
	fakeAT.AccessToken.IDToken.UPN = "B"
	ar2, err := client.AcquireTokenByAuthCode(ctx, "code", "http://localhost", tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if ar1.AccessToken == ar2.AccessToken {
		t.Fatal("expected different access tokens")
	}

	// cache should now have an access token for each account
	for _, ar := range []AuthResult{ar1, ar2} {
		actual, err := client.AcquireTokenSilent(ctx, tokenScope, WithSilentAccount(ar.Account))
		if err != nil {
			t.Fatal(err)
		}
		if actual.AccessToken != ar.AccessToken {
			t.Fatalf("expected %q, got %q", ar.AccessToken, actual.AccessToken)
		}
	}
}

func TestAuthorityValidation(t *testing.T) {
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"", "https://login.microsoftonline.com", "http://login.microsoftonline.com/tenant"} {
		t.Run(a, func(t *testing.T) {
			_, err := New(a, fakeClientID, cred)
			if err == nil || !strings.Contains(err.Error(), "authority") {
				t.Fatalf("expected an error about the invalid authority, got %v", err)
			}
		})
	}
}

func TestInvalidCredential(t *testing.T) {
	for _, cred := range []Credential{
		{},
		NewCredFromAssertionCallback(nil),
	} {
		t.Run("", func(t *testing.T) {
			_, err := New(fakeAuthority, fakeClientID, cred)
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestNewCredFromCert(t *testing.T) {
	for _, file := range []struct {
		path          string
		numCerts      int
		testAuthority string
	}{
		{"../testdata/test-cert.pem", 1, fakeAuthority},
		{"../testdata/test-cert.pem", 1, "https://fs.msidlab8.com/adfs"},
		{"../testdata/test-cert.pem", 1, "https://some.url.dsts.core.azure-test.net/dstsv2/7a433bfc-2514-4697-b467-e0933190487f"},
		{"../testdata/test-cert-chain.pem", 2, fakeAuthority},
		{"../testdata/test-cert-chain-reverse.pem", 2, fakeAuthority},
	} {
		f, err := os.Open(filepath.Clean(file.path))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		pemData, err := io.ReadAll(f)
		if err != nil {
			t.Fatal(err)
		}
		certs, key, err := CertFromPEM(pemData, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(certs) != file.numCerts {
			t.Fatalf("expected %d certs, got %d", file.numCerts, len(certs))
		}
		expectedCerts := make(map[string]struct{}, len(certs))
		for _, cert := range certs {
			expectedCerts[base64.StdEncoding.EncodeToString(cert.Raw)] = struct{}{}
		}
		k, ok := key.(*rsa.PrivateKey)
		if !ok {
			t.Fatal("expected an RSA private key")
		}
		verifyingKey := &k.PublicKey
		cred, err := NewCredFromCert(certs, key)
		if err != nil {
			t.Fatal(err)
		}
		for _, sendX5c := range []bool{false, true} {
			opts := []Option{}
			if sendX5c {
				opts = append(opts, WithX5C())
			}
			t.Run(fmt.Sprintf("%s/%v", filepath.Base(file.path), sendX5c), func(t *testing.T) {
				client, err := fakeClient(accesstokens.TokenResponse{
					AccessToken:   token,
					ExpiresOn:     time.Now().Add(time.Hour),
					GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
				}, cred, file.testAuthority, opts...)
				if err != nil {
					t.Fatal(err)
				}
				// the test fake passes assertions generated by the credential to this function
				validated := false
				client.base.Token.AccessTokens.(*fake.AccessTokens).ValidateAssertion = func(s string) {
					validated = true
					tk, err := jwt.Parse(s, func(tk *jwt.Token) (interface{}, error) {
						algo := jwt.SigningMethodPS256.Alg()
						if file.testAuthority != fakeAuthority {
							algo = jwt.SigningMethodRS256.Alg()
						}
						if tk.Method.Alg() != algo {
							t.Fatalf("unexpected signing method %v", tk.Method.Alg())
						}
						return verifyingKey, nil
					})
					if err != nil {
						t.Fatal(err)
					}
					if !tk.Valid {
						t.Fatal("token not valid")
					}
					// x5c header should be set iff the sendX5c is true
					if x5c, ok := tk.Header["x5c"]; ok != sendX5c {
						t.Fatal("x5c should be set only when application passed WithX5C option")
					} else if ok {
						if x := len(x5c.([]interface{})); x > file.numCerts {
							t.Fatalf("x5c contains %d certs; expected %d", x, file.numCerts)
						}
						// x5c must contain all the file's certs, signing cert first
						for i, cert := range x5c.([]interface{}) {
							s := cert.(string)
							if _, ok := expectedCerts[s]; ok {
								delete(expectedCerts, s)
							} else {
								t.Fatal("x5c contains an unexpected cert")
							}
							if i == 0 {
								decoded, err := base64.StdEncoding.DecodeString(s)
								if err != nil {
									t.Fatal(err)
								}
								parsed, err := x509.ParseCertificate(decoded)
								if err != nil {
									t.Fatal(err)
								}
								if !verifyingKey.Equal(parsed.PublicKey) {
									t.Fatal("signing cert must appear first in x5c")
								}
							}
						}
						if len(expectedCerts) > 0 {
							t.Fatal("x5c header is missing a cert")
						}
					}
				}
				tk, err := client.AcquireTokenByCredential(context.Background(), tokenScope)
				if err != nil {
					t.Fatal(err)
				}
				if tk.AccessToken != token {
					t.Fatalf("unexpected access token %s", tk.AccessToken)
				}
				if !validated {
					t.Fatal("assertion validation function wasn't called")
				}
			})
		}
	}
}

func TestNewCredFromCertError(t *testing.T) {
	data, err := os.ReadFile("../testdata/test-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	certs, key, err := CertFromPEM(data, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		certs []*x509.Certificate
		key   crypto.PrivateKey
	}{
		{nil, nil},
		{certs, nil},
		{nil, key},
		{[]*x509.Certificate{}, nil},
		{[]*x509.Certificate{}, key},
		{[]*x509.Certificate{nil}, nil},
		{[]*x509.Certificate{nil}, key},
	} {
		t.Run("", func(t *testing.T) {
			_, err := NewCredFromCert(test.certs, test.key)
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}

	// the key in this file doesn't match the cert loaded above
	if data, err = os.ReadFile("../testdata/test-cert-chain.pem"); err != nil {
		t.Fatal(err)
	}
	if _, key, err = CertFromPEM(data, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = NewCredFromCert(certs, key); err == nil {
		t.Fatal("expected an error because key doesn't match certs")
	}
}

func TestNewCredFromTokenProvider(t *testing.T) {
	expectedToken := "expected token"
	called := false
	expiresIn := 18000
	refreshOn := expiresIn / 2
	key := struct{}{}
	ctx := context.WithValue(context.Background(), key, true)
	cred := NewCredFromTokenProvider(func(c context.Context, tp exported.TokenProviderParameters) (exported.TokenProviderResult, error) {
		if called {
			t.Fatal("expected exactly one token provider invocation")
		}
		called = true
		if v := c.Value(key); v == nil || !v.(bool) {
			t.Fatal("callback received unexpected context")
		}
		if tp.CorrelationID == "" {
			t.Fatal("expected CorrelationID")
		}
		if v := fmt.Sprint(tp.Scopes); v != fmt.Sprint(tokenScope) {
			t.Fatalf(`unexpected scopes "%v"`, v)
		}
		return exported.TokenProviderResult{
			AccessToken:      expectedToken,
			ExpiresInSeconds: expiresIn,
			RefreshInSeconds: refreshOn,
		}, nil
	})
	client, err := New(fakeAuthority, fakeClientID, cred, WithHTTPClient(&errorClient{}))
	if err != nil {
		t.Fatal(err)
	}
	ar, err := client.AcquireTokenByCredential(ctx, tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("token provider wasn't invoked")
	}
	if !isTimeSame(ar.ExpiresOn, expiresIn) {
		t.Fatalf("expected ExpiresOn ~= %d seconds, got %d", expiresIn, ar.ExpiresOn.Second())
	}
	if !isTimeSame(ar.Metadata.RefreshOn, refreshOn) {
		t.Fatalf("expected RefreshOn ~= %d seconds from now, got %d", refreshOn, ar.Metadata.RefreshOn.Second())
	}

	if ar.AccessToken != expectedToken {
		t.Fatalf(`unexpected token "%s"`, ar.AccessToken)
	}
	ar, err = client.AcquireTokenSilent(context.Background(), tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if ar.AccessToken != expectedToken {
		t.Fatalf(`unexpected token "%s"`, ar.AccessToken)
	}
}
func TestRefreshInMultipleRequests(t *testing.T) {
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	firstToken := "first token"
	secondToken := "new token"
	lmo := "login.microsoftonline.com"
	refreshIn := 43200
	expiresIn := 86400

	originalTime := base.Now
	defer func() {
		base.Now = originalTime
	}()
	// Create a mock client and append mock responses
	mockClient := mock.NewClient()

	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, "firstTenant")))
	mockClient.AppendResponse(
		mock.WithBody([]byte(fmt.Sprintf(`{"access_token":%q,"expires_in":%d,"refresh_in":%d,"token_type":"Bearer"}`, firstToken, expiresIn, refreshIn))),
	)
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, "secondTenant")))
	mockClient.AppendResponse(
		mock.WithBody([]byte(fmt.Sprintf(`{"access_token":%q,"expires_in":%d,"refresh_in":%d,"token_type":"Bearer"}`, firstToken, expiresIn, refreshIn))),
	)
	// Create the client instance
	client, err := New(fmt.Sprintf(authorityFmt, lmo, "firstTenant"), fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}
	// Acquire the first token for first tenant
	ar, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithTenantID("firstTenant"))
	if err != nil {
		t.Fatal(err)
	}
	// Assert the first token is returned
	if ar.AccessToken != firstToken {
		t.Fatalf("wanted %q, got %q", firstToken, ar.AccessToken)
	}
	// Acquire the first token for second tenant
	arSecond, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithTenantID("secondTenant"))
	if err != nil {
		t.Fatal(err)
	}
	if arSecond.AccessToken != firstToken {
		t.Fatalf("wanted %q, got %q", firstToken, arSecond.AccessToken)
	}
	fixedTime := time.Now().Add(time.Duration(43400) * time.Second)
	base.Now = func() time.Time {
		return fixedTime
	}
	var wg sync.WaitGroup
	ch := make(chan error, 1)
	firstTenantChecker := false
	secondTenantChecker := false
	respond := func(r *http.Request) {
		if s := strings.SplitN(r.URL.Path, "/", 3); len(s) == 3 {
			switch s[1] {
			case "firstTenant":
				firstTenantChecker = true
			case "secondTenant":
				secondTenantChecker = true
			default:
				t.Error("unexpected token request URL: " + r.URL.String())
			}
		} else {
			t.Error("unexpected token request URL: " + r.URL.String())
		}
	}
	body := []byte(fmt.Sprintf(`{"access_token":%q,"expires_in":%d,"refresh_in":%d,"token_type":"Bearer"}`, secondToken, expiresIn, refreshIn+44200))
	mockClient.AppendResponse(mock.WithBody(body), mock.WithCallback(respond))
	mockClient.AppendResponse(mock.WithBody(body), mock.WithCallback(respond))

	for i := 0; i < 10000; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := client.AcquireTokenSilent(context.Background(), tokenScope, WithTenantID("firstTenant"))
			if err != nil {
				select {
				case ch <- err:
				default:
				}
				return
			}
		}()
		go func() {
			defer wg.Done()
			_, err := client.AcquireTokenSilent(context.Background(), tokenScope, WithTenantID("secondTenant"))
			if err != nil {
				select {
				case ch <- err:
				default:
				}
				return
			}
		}()
	}
	wg.Wait()
	select {
	case err := <-ch:
		t.Fatal(err)
	default:
	}
	if !secondTenantChecker && !firstTenantChecker {
		t.Error("Error should be called at least once")
	}
}

func TestConcurrentRequests(t *testing.T) {
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	firstToken := "first token"
	lmo := "login.microsoftonline.com"
	refreshIn := 43200
	expiresIn := 86400

	originalTime := base.Now
	defer func() {
		base.Now = originalTime
	}()
	// Create a mock client and append mock responses
	mockClient := mock.NewClient()

	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, "firstTenant")))
	mockClient.AppendResponse(
		mock.WithBody([]byte(fmt.Sprintf(`{"access_token":%q,"expires_in":%d,"refresh_in":%d,"token_type":"Bearer"}`, firstToken, expiresIn, refreshIn))),
	)
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, "secondTenant")))
	mockClient.AppendResponse(
		mock.WithBody([]byte(fmt.Sprintf(`{"access_token":%q,"expires_in":%d,"refresh_in":%d,"token_type":"Bearer"}`, firstToken, expiresIn, refreshIn))),
	)
	// Create the client instance
	client, err := New(fmt.Sprintf(authorityFmt, lmo, "firstTenant"), fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}
	// Acquire the first token for first tenant
	ar, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithTenantID("firstTenant"))
	if err != nil {
		t.Fatal(err)
	}
	// Assert the first token is returned
	if ar.AccessToken != firstToken {
		t.Fatalf("wanted %q, got %q", firstToken, ar.AccessToken)
	}
	// Acquire the first token for second tenant
	arSecond, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithTenantID("secondTenant"))
	if err != nil {
		t.Fatal(err)
	}
	if arSecond.AccessToken != firstToken {
		t.Fatalf("wanted %q, got %q", firstToken, arSecond.AccessToken)
	}
	fixedTime := time.Now().Add(time.Duration(43400) * time.Second)
	base.Now = func() time.Time {
		return fixedTime
	}
	present := make(chan string, 2)
	proceed := make(chan struct{})
	wg := sync.WaitGroup{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, tenant := range []string{"firstTenant", "secondTenant"} {
		wg.Add(1)
		mockClient.AppendResponse(
			mock.WithBody(mock.GetAccessTokenBody(tenant, "", "", "", expiresIn, refreshIn)),
			mock.WithCallback(func(r *http.Request) {
				if s := strings.SplitN(r.URL.Path, "/", 3); len(s) == 3 {
					present <- s[1]
					<-proceed
				} else {
					t.Error("unexpected token request URL: " + r.URL.String())
				}
			}),
		)
		go func(id string) {
			defer wg.Done()
			if _, err := client.AcquireTokenSilent(ctx, tokenScope, WithTenantID(id)); err != nil {
				t.Error("Unexpected error", err)
			}
		}(tenant)
	}
	for a, b := false, false; !(a && b); {
		select {
		case <-ctx.Done():
			t.Fatal("timed out waiting for both goroutines to refresh")
		case g := <-present:
			switch g {
			case "firstTenant":
				a = true
			case "secondTenant":
				b = true
			default:
				t.Fatal("unexpected goroutine: " + g)
			}
			proceed <- struct{}{}
		}
	}
	close(proceed)
	wg.Wait()
}

func TestRefreshIn(t *testing.T) {
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	firstToken := "first token"
	secondToken := "new token"
	lmo := "login.microsoftonline.com"
	tenant := "tenant"
	refreshIn := 43200
	expiresIn := 86400
	for _, tt := range []struct {
		shouldGetNewToken  bool
		secondRequestAfter int
		shouldReturnError  bool
	}{
		{secondRequestAfter: 40000, shouldGetNewToken: false},                          // from cache
		{secondRequestAfter: 43400, shouldGetNewToken: true},                           // refresh in expired so new token
		{secondRequestAfter: 40000, shouldGetNewToken: false, shouldReturnError: true}, // refresh in not expired but refresh failed so new token
		{secondRequestAfter: 80000, shouldGetNewToken: true, shouldReturnError: false}, // refresh in expired but refresh failed so new token
		{secondRequestAfter: 1003400, shouldGetNewToken: true},
	} {
		name := "token doesn't need refresh"
		t.Run(name, func(t *testing.T) {
			originalTime := base.Now
			defer func() {
				base.Now = originalTime
			}()
			// Create a mock client and append mock responses
			mockClient := mock.NewClient()

			mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
			mockClient.AppendResponse(
				mock.WithBody([]byte(fmt.Sprintf(`{"access_token":%q,"expires_in":%d,"refresh_in":%d,"token_type":"Bearer"}`, firstToken, expiresIn, refreshIn))),
			)
			if tt.shouldReturnError {
				mockClient.AppendResponse(
					mock.WithHTTPStatusCode(http.StatusBadGateway),
					mock.WithBody([]byte(fmt.Sprintf(`{"access_token":%q,"expires_in":%d,"refresh_in":%d,"token_type":"Bearer"}`, firstToken, expiresIn, refreshIn))),
				)
			} else {
				mockClient.AppendResponse(
					mock.WithBody([]byte(fmt.Sprintf(`{"access_token":%q,"expires_in":%d,"refresh_in":%d,"token_type":"Bearer"}`, secondToken, expiresIn, refreshIn))),
				)
			}

			// Create the client instance
			client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
			if err != nil {
				t.Fatal(err)
			}
			// Acquire the first token
			ar, err := client.AcquireTokenByCredential(context.Background(), tokenScope)
			if err != nil {
				t.Fatal(err)
			}
			// Assert the first token is returned
			if ar.AccessToken != firstToken {
				t.Fatalf("wanted %q, got %q", firstToken, ar.AccessToken)
			}
			if ar.Metadata.RefreshOn.IsZero() {
				t.Fatal("RefreshOn shouldn't be zero")
			}
			if !isTimeSame(ar.Metadata.RefreshOn, refreshIn) {
				t.Fatalf("expected RefreshOn ~= %d seconds from now, got %d", refreshIn, ar.Metadata.RefreshOn.Second())
			}
			fixedTime := time.Now().Add(time.Duration(tt.secondRequestAfter) * time.Second)
			base.Now = func() time.Time {
				return fixedTime
			}
			ar, err = client.AcquireTokenSilent(context.Background(), tokenScope)
			if err != nil {
				t.Fatal(err)
			}
			if ar.Metadata.TokenSource != TokenSourceCache && !tt.shouldGetNewToken {
				t.Fatal("should have returned from cache.")
			}
			if (ar.AccessToken == secondToken) != tt.shouldGetNewToken {
				t.Fatalf("wanted %q, got %q", secondToken, ar.AccessToken)
			}
		})
	}
}

func isTimeSame(t time.Time, expectedSeconds int) bool {
	v := int(time.Until(t).Seconds())
	return !(v < expectedSeconds-2 || v > expectedSeconds+2)
}

func TestNewCredFromTokenProviderError(t *testing.T) {
	expectedError := "something went wrong"
	cred := NewCredFromTokenProvider(func(ctx context.Context, tpp exported.TokenProviderParameters) (exported.TokenProviderResult, error) {
		return exported.TokenProviderResult{}, errors.New(expectedError)
	})
	client, err := New(fakeAuthority, fakeClientID, cred)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AcquireTokenByCredential(context.Background(), tokenScope)
	if err == nil || !strings.Contains(err.Error(), expectedError) {
		t.Fatalf(`unexpected error "%v"`, err)
	}
}

func TestTokenProviderResultForRefreshIn(t *testing.T) {
	accessToken, claims, tenant := "at", "claims", "tenant"
	cred := NewCredFromTokenProvider(func(ctx context.Context, tpp TokenProviderParameters) (TokenProviderResult, error) {
		if tpp.Claims != claims {
			t.Fatalf(`unexpected claims "%s"`, tpp.Claims)
		}
		if tpp.TenantID != tenant {
			t.Fatalf(`unexpected tenant "%s"`, tpp.TenantID)
		}
		return TokenProviderResult{AccessToken: accessToken, ExpiresInSeconds: 36000, RefreshInSeconds: 18000}, nil
	})
	client, err := New(fakeAuthority, fakeClientID, cred, WithHTTPClient(&errorClient{}))
	if err != nil {
		t.Fatal(err)
	}
	ar, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithClaims(claims), WithTenantID(tenant))
	if err != nil {
		t.Fatal(err)
	}
	if !isTimeSame(ar.Metadata.RefreshOn, 18000) {
		t.Fatal("RefreshOn should be 18000 seconds from now")
	}
	if ar.AccessToken != accessToken {
		t.Fatalf(`unexpected access token "%s"`, ar.AccessToken)
	}
}

func TestTokenProviderOptions(t *testing.T) {
	accessToken, claims, tenant := "at", "claims", "tenant"
	cred := NewCredFromTokenProvider(func(ctx context.Context, tpp TokenProviderParameters) (TokenProviderResult, error) {
		if tpp.Claims != claims {
			t.Fatalf(`unexpected claims "%s"`, tpp.Claims)
		}
		if tpp.TenantID != tenant {
			t.Fatalf(`unexpected tenant "%s"`, tpp.TenantID)
		}
		return TokenProviderResult{AccessToken: accessToken, ExpiresInSeconds: 3600}, nil
	})
	client, err := New(fakeAuthority, fakeClientID, cred, WithHTTPClient(&errorClient{}))
	if err != nil {
		t.Fatal(err)
	}
	ar, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithClaims(claims), WithTenantID(tenant))
	if err != nil {
		t.Fatal(err)
	}
	if ar.AccessToken != accessToken {
		t.Fatalf(`unexpected access token "%s"`, ar.AccessToken)
	}
}

// testCache is a simple in-memory cache.ExportReplace implementation
type testCache map[string][]byte

func (c testCache) Export(ctx context.Context, m cache.Marshaler, h cache.ExportHints) error {
	if v, err := m.Marshal(); err == nil {
		c[h.PartitionKey] = v
	}
	return nil
}

func (c testCache) Replace(ctx context.Context, u cache.Unmarshaler, h cache.ReplaceHints) error {
	if v, has := c[h.PartitionKey]; has {
		_ = u.Unmarshal(v)
	}
	return nil
}

func TestWithCache(t *testing.T) {
	cache := make(testCache)
	accessToken := "*"
	lmo := "login.microsoftonline.com"
	tenantA, tenantB := "a", "b"
	authorityA, authorityB := fmt.Sprintf(authorityFmt, lmo, tenantA), fmt.Sprintf(authorityFmt, lmo, tenantB)
	mockClient := mock.NewClient()

	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenantA)))
	mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody(accessToken, mock.GetIDToken(tenantA, authorityA), "", "", 3600, 0)))

	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(authorityA, fakeClientID, cred, WithCache(&cache), WithHTTPClient(mockClient))
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
	client, err = New(authorityB, fakeClientID, cred, WithCache(&cache), WithHTTPClient(mockClient))
	if err != nil {
		t.Fatal(err)
	}
	// this should succeed because the cache contains an access token from tenantA
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenantA)))
	ar, err = client.AcquireTokenSilent(context.Background(), tokenScope, WithSilentAccount(account), WithTenantID(tenantA))
	if err != nil {
		t.Fatal(err)
	}
	if ar.AccessToken != accessToken {
		t.Fatalf(`unexpected access token "%s"`, ar.AccessToken)
	}
	// this should fail because the cache doesn't contain an access token from tenantB
	ar, err = client.AcquireTokenSilent(context.Background(), tokenScope, WithSilentAccount(account))
	if err == nil {
		t.Fatal("expected an error because the cache doesn't have an appropriate access token")
	}
}

func TestWithClaims(t *testing.T) {
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	accessToken := "at"
	lmo, tenant := "login.microsoftonline.com", "tenant"
	authority := fmt.Sprintf(authorityFmt, lmo, tenant)
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
				t.Fatalf("expected 1 value for claims, got %d", len(claims))
			}
			var actual map[string]any
			if err := json.Unmarshal([]byte(claims[0]), &actual); err != nil {
				t.Fatal(err)
			}
			if diff := pretty.Compare(expected, actual); diff != "" {
				t.Fatal(diff)
			}
		}
		for _, method := range []string{"authcode", "authcodeURL", "credential", "obo"} {
			t.Run(method, func(t *testing.T) {
				mockClient := mock.NewClient()

				clientInfo, idToken, refreshToken := "", "", ""
				if method == "obo" {
					clientInfo = base64.RawStdEncoding.EncodeToString([]byte(`{"uid":"uid","utid":"utid"}`))
					idToken = mock.GetIDToken(tenant, authority)
					refreshToken = "rt"
					// TODO: OBO does instance discovery twice before first token request https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/351
					mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenant)))
				}
				mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenant)))
				mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
				mockClient.AppendResponse(
					mock.WithBody(mock.GetAccessTokenBody(accessToken, idToken, refreshToken, clientInfo, 3600, 0)),
					mock.WithCallback(func(r *http.Request) {
						if err := r.ParseForm(); err != nil {
							t.Fatal(err)
						}
						validate(t, r.Form)
					}),
				)
				client, err := New(authority, fakeClientID, cred, WithClientCapabilities(test.capabilities), WithHTTPClient(mockClient))
				if err != nil {
					t.Fatal(err)
				}
				if _, err = client.AcquireTokenSilent(context.Background(), tokenScope); err == nil {
					t.Fatal("silent authentication should fail because the cache is empty")
				}
				ctx := context.Background()
				var ar AuthResult
				switch method {
				case "authcode":
					ar, err = client.AcquireTokenByAuthCode(ctx, "code", localhost, tokenScope, WithClaims(test.claims))
				case "authcodeURL":
					u := ""
					if u, err = client.AuthCodeURL(ctx, fakeClientID, localhost, tokenScope, WithClaims(test.claims)); err == nil {
						var parsed *url.URL
						if parsed, err = url.Parse(u); err == nil {
							validate(t, parsed.Query())
							return // didn't acquire a token, no need for further validation
						}
					}
				case "credential":
					ar, err = client.AcquireTokenByCredential(ctx, tokenScope, WithClaims(test.claims))
				case "obo":
					ar, err = client.AcquireTokenOnBehalfOf(ctx, "assertion", tokenScope, WithClaims(test.claims))
				case "password":
					ar, err = client.AcquireTokenByUsernamePassword(ctx, tokenScope, "username", "password", WithClaims(test.claims))
				default:
					t.Fatalf("test bug: no test for %s", method)
				}
				if err != nil {
					t.Fatal(err)
				}
				if ar.AccessToken != accessToken {
					t.Fatalf(`unexpected access token "%s"`, ar.AccessToken)
				}
				// silent auth should now succeed, provided no claims are requested, because the client has cached an access token
				if method == "obo" {
					ar, err = client.AcquireTokenOnBehalfOf(ctx, "assertion", tokenScope)
				} else {
					ar, err = client.AcquireTokenSilent(ctx, tokenScope)
				}
				if err != nil {
					t.Fatal(err)
				}
				if ar.AccessToken != accessToken {
					t.Fatalf(`unexpected access token "%s"`, ar.AccessToken)
				}
				if test.claims != "" {
					if _, err = client.AcquireTokenSilent(ctx, tokenScope, WithClaims(test.claims)); err == nil {
						t.Fatal("AcquireTokenSilent should fail when given claims")
					}
					if method == "obo" {
						// client has cached access and refresh tokens. When given claims, it should redeem a refresh token for a new access token.
						newToken := "new-access-token"
						mockClient.AppendResponse(
							mock.WithBody(mock.GetAccessTokenBody(newToken, idToken, "", clientInfo, 3600, 0)),
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
						ar, err = client.AcquireTokenOnBehalfOf(ctx, "assertion", tokenScope, WithClaims(test.claims))
						if err != nil {
							t.Fatal(err)
						}
						if ar.AccessToken != newToken {
							t.Fatalf(`unexpected access token "%s"`, ar.AccessToken)
						}
					}
				}
			})
		}
	}
}

func TestWithTenantID(t *testing.T) {
	accessToken := "*"
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
		for _, method := range []string{"authcode", "authcodeURL", "credential", "obo"} {
			t.Run(method, func(t *testing.T) {
				cred, err := NewCredFromSecret(fakeSecret)
				if err != nil {
					t.Fatal(err)
				}
				idToken, refreshToken, URL := "", "", ""
				mockClient := mock.NewClient()

				if method == "obo" {
					idToken = mock.GetIDToken(test.tenant, test.authority)
					refreshToken = "refresh-token"
					// TODO: OBO does instance discovery twice before first token request https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/351
					mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, test.tenant)))
				}
				mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, test.tenant)))
				mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, test.tenant)))
				mockClient.AppendResponse(
					mock.WithBody(mock.GetAccessTokenBody(accessToken, idToken, refreshToken, "", 3600, 0)),
					mock.WithCallback(func(r *http.Request) { URL = r.URL.String() }),
				)
				client, err := New(test.authority, fakeClientID, cred, WithHTTPClient(mockClient))
				if err != nil {
					t.Fatal(err)
				}
				ctx := context.Background()
				if _, err = client.AcquireTokenSilent(ctx, tokenScope, WithTenantID(test.tenant)); err == nil {
					t.Fatal("silent auth should fail because the cache is empty")
				}
				var ar AuthResult
				switch method {
				case "authcode":
					ar, err = client.AcquireTokenByAuthCode(ctx, "auth code", localhost, tokenScope, WithTenantID(test.tenant))
				case "authcodeURL":
					URL, err = client.AuthCodeURL(ctx, fakeClientID, localhost, tokenScope, WithTenantID(test.tenant))
				case "credential":
					ar, err = client.AcquireTokenByCredential(ctx, tokenScope, WithTenantID(test.tenant))
				case "obo":
					ar, err = client.AcquireTokenOnBehalfOf(ctx, "assertion", tokenScope, WithTenantID(test.tenant))
				default:
					t.Fatalf("test bug: no test for %s", method)
				}
				if err != nil {
					if test.expectError {
						return
					}
					t.Fatal(err)
				} else if test.expectError {
					t.Fatal("expected an error")
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
				// silent authentication should now succeed for the given tenant...
				if method == "obo" {
					if ar, err = client.AcquireTokenOnBehalfOf(ctx, "assertion", tokenScope, WithTenantID(test.tenant)); err != nil {
						t.Fatal(err)
					}
				} else if ar, err = client.AcquireTokenSilent(ctx, tokenScope, WithTenantID(test.tenant)); err != nil {
					t.Fatal(err)
				}
				if ar.AccessToken != accessToken {
					t.Fatal("cached access token should match the one returned by AcquireToken...")
				}
				// ...but fail for another tenant unless we're authenticating OBO, in which case we have a refresh token
				otherTenant := "not-" + test.tenant
				if method == "obo" {
					mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, test.tenant)))
					mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody(accessToken, idToken, refreshToken, "", 3600, 0)))
					if _, err = client.AcquireTokenOnBehalfOf(ctx, "assertion", tokenScope, WithTenantID(otherTenant)); err != nil {
						t.Fatal(err)
					}
				} else if _, err = client.AcquireTokenSilent(ctx, tokenScope, WithTenantID(otherTenant)); err == nil {
					t.Fatal("expected an error")
				}
			})
		}
	}

	// if every auth call specifies a different tenant, Client shouldn't send requests to its configured authority
	t.Run("enables fake authority", func(t *testing.T) {
		host := "host"
		defaultTenant := "default"
		cred, err := NewCredFromSecret(fakeSecret)
		if err != nil {
			t.Fatal(err)
		}
		URL := ""
		mockClient := mock.NewClient()

		client, err := New(fmt.Sprintf(authorityFmt, host, defaultTenant), fakeClientID, cred, WithHTTPClient(mockClient))
		if err != nil {
			t.Fatal(err)
		}
		checkForWrongTenant := func(r *http.Request) {
			if u := r.URL.String(); strings.Contains(u, defaultTenant) {
				t.Fatalf("unexpected request to the default authority: %q", u)
			}
		}
		ctx := context.Background()
		for i := 0; i < 3; i++ {
			tenant := fmt.Sprint(i)
			expected := fmt.Sprintf(authorityFmt, host, tenant)
			// TODO: prevent redundant discovery requests https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/351
			mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(host, tenant)), mock.WithCallback(checkForWrongTenant))
			mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(host, tenant)), mock.WithCallback(checkForWrongTenant))
			mockClient.AppendResponse(
				mock.WithBody(mock.GetAccessTokenBody(accessToken, "", "", "", 3600, 0)),
				mock.WithCallback(func(r *http.Request) { URL = r.URL.String() }),
			)
			if i == 0 {
				// TODO: see above (first silent auth rediscovers instance metadata)
				mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(host, tenant)), mock.WithCallback(checkForWrongTenant))
			}
			ar, err := client.AcquireTokenByAuthCode(ctx, "auth code", localhost, tokenScope, WithTenantID(tenant))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(URL, expected) {
				t.Fatalf(`expected "%s", got "%s"`, expected, URL)
			}
			if ar.AccessToken != accessToken {
				t.Fatalf("unexpected access token %q", ar.AccessToken)
			}
			// silent authentication should now succeed for the given tenant...
			if ar, err = client.AcquireTokenSilent(ctx, tokenScope, WithTenantID(tenant)); err != nil {
				t.Fatal(err)
			}
			if ar.AccessToken != accessToken {
				t.Fatal("cached access token should match the one returned by AcquireToken...")
			}
			// ...but fail for another tenant
			otherTenant := "not-" + tenant
			if _, err = client.AcquireTokenSilent(ctx, tokenScope, WithTenantID(otherTenant)); err == nil {
				t.Fatal("expected an error")
			}
		}
	})
}

func TestWithInstanceDiscovery(t *testing.T) {
	accessToken := "*"
	host := "stack.local"
	stackurl := fmt.Sprintf("https://%s/", host)
	for _, tenant := range []string{
		"adfs",
		"98b8267d-e97f-426e-8b3f-7956511fd63f",
	} {
		for _, method := range []string{"authcode", "credential", "obo"} {
			t.Run(method, func(t *testing.T) {
				authority := stackurl + tenant
				cred, err := NewCredFromSecret(fakeSecret)
				if err != nil {
					t.Fatal(err)
				}
				idToken, refreshToken := "", ""
				mockClient := mock.NewClient()

				if method == "obo" {
					idToken = mock.GetIDToken(tenant, authority)
					refreshToken = "refresh-token"
				}
				mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(stackurl, tenant)))
				mockClient.AppendResponse(
					mock.WithBody(mock.GetAccessTokenBody(accessToken, idToken, refreshToken, "", 3600, 0)),
				)
				client, err := New(authority, fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
				if err != nil {
					t.Fatal(err)
				}
				ctx := context.Background()
				if _, err = client.AcquireTokenSilent(ctx, tokenScope); err == nil {
					t.Fatal("silent auth should fail because the cache is empty")
				}
				var ar AuthResult
				switch method {
				case "authcode":
					ar, err = client.AcquireTokenByAuthCode(ctx, "auth code", localhost, tokenScope)
				case "credential":
					ar, err = client.AcquireTokenByCredential(ctx, tokenScope)
				case "obo":
					ar, err = client.AcquireTokenOnBehalfOf(ctx, "assertion", tokenScope)
				case "password":
					ar, err = client.AcquireTokenByUsernamePassword(ctx, tokenScope, "username", "password")
				default:
					t.Fatal("test bug: no test for " + method)
				}
				if err != nil {
					t.Fatal(err)
				}
				if ar.AccessToken != accessToken {
					t.Fatalf(`unexpected access token "%s"`, ar.AccessToken)
				}
				if method == "obo" {
					if ar, err = client.AcquireTokenOnBehalfOf(ctx, "assertion", tokenScope); err != nil {
						t.Fatal(err)
					}
				} else if ar, err = client.AcquireTokenSilent(ctx, tokenScope); err != nil {
					t.Fatal(err)
				}
				if ar.AccessToken != accessToken {
					t.Fatal("cached access token should match the one returned by AcquireToken...")
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
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	idToken, refreshToken, URL := "", "", ""
	mockClient := mock.NewClient()

	//2 calls to instance discovery are made because Host is not trusted
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(host, tenant)))
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(host, tenant)))
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(host, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody(accessToken, idToken, refreshToken, "", 3600, 0)),
		mock.WithCallback(func(r *http.Request) { URL = r.URL.String() }),
	)
	client, err := New(authority, fakeClientID, cred, WithHTTPClient(mockClient))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = client.AcquireTokenSilent(ctx, tokenScope); err == nil {
		t.Fatal("silent auth should fail because the cache is empty")
	}
	var ar AuthResult
	ar, err = client.AcquireTokenByAuthCode(ctx, "auth code", localhost, tokenScope)
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
	upn := "user@localhost"
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(fakeAuthority, fakeClientID, cred, WithHTTPClient(&errorClient{}))
	if err != nil {
		t.Fatal(err)
	}
	client.base.Token.Resolver = &fake.ResolveEndpoints{}
	for _, expectHint := range []bool{true, false} {
		t.Run(fmt.Sprint(expectHint), func(t *testing.T) {
			opts := []AuthCodeURLOption{}
			if expectHint {
				opts = append(opts, WithLoginHint(upn))
			}
			u, err := client.AuthCodeURL(context.Background(), "id", localhost, tokenScope, opts...)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := url.Parse(u)
			if err != nil {
				t.Fatal(err)
			}
			if !parsed.Query().Has("login_hint") {
				if !expectHint {
					return
				}
				t.Fatal("expected a login hint")
			} else if !expectHint {
				t.Fatal("expected no login hint")
			}
			if actual := parsed.Query()["login_hint"]; len(actual) != 1 || actual[0] != upn {
				t.Fatalf(`unexpected login_hint "%v"`, actual)
			}
		})
	}
}

func TestWithDomainHint(t *testing.T) {
	domain := "contoso.com"
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(fakeAuthority, fakeClientID, cred, WithHTTPClient(&errorClient{}))
	if err != nil {
		t.Fatal(err)
	}
	client.base.Token.Resolver = &fake.ResolveEndpoints{}
	for _, expectHint := range []bool{true, false} {
		t.Run(fmt.Sprint(expectHint), func(t *testing.T) {
			var opts []AuthCodeURLOption
			if expectHint {
				opts = append(opts, WithDomainHint(domain))
			}
			u, err := client.AuthCodeURL(context.Background(), "id", localhost, tokenScope, opts...)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := url.Parse(u)
			if err != nil {
				t.Fatal(err)
			}
			if !parsed.Query().Has("domain_hint") {
				if !expectHint {
					return
				}
				t.Fatal("expected a domain hint")
			} else if !expectHint {
				t.Fatal("expected no domain hint")
			}
			if actual := parsed.Query()["domain_hint"]; len(actual) != 1 || actual[0] != domain {
				t.Fatalf(`unexpected domain_hint "%v"`, actual)
			}
		})
	}
}

func TestWithAuthenticationScheme(t *testing.T) {
	ctx := context.Background()
	authScheme := mock.NewTestAuthnScheme()
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	client, err := fakeClient(accesstokens.TokenResponse{
		AccessToken:   token,
		ExpiresOn:     time.Now().Add(1 * time.Hour),
		ExtExpiresOn:  internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
		GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
		TokenType:     "TokenType",
	}, cred, fakeAuthority)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.AcquireTokenByCredential(ctx, tokenScope, WithAuthenticationScheme(authScheme))
	if err != nil {
		t.Fatal(err)
	}
	if result.AccessToken != fmt.Sprintf(mock.Authnschemeformat, token) {
		t.Fatalf(`unexpected access token "%s"`, result.AccessToken)
	}
	result, err = client.AcquireTokenSilent(ctx, tokenScope, WithAuthenticationScheme(authScheme))
	if err != nil {
		t.Fatal(err)
	}
	if result.AccessToken != fmt.Sprintf(mock.Authnschemeformat, token) {
		t.Fatalf(`unexpected access token "%s"`, result.AccessToken)
	}
}

func TestAcquireTokenByCredentialFromDSTS(t *testing.T) {
	tests := map[string]struct {
		cred string
	}{
		"secret":           {cred: "fake_secret"},
		"signed assertion": {cred: "fake_assertion"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cred, err := NewCredFromSecret(test.cred)
			if err != nil {
				t.Fatal(err)
			}
			client, err := fakeClient(accesstokens.TokenResponse{
				AccessToken:   token,
				ExpiresOn:     time.Now().Add(1 * time.Hour),
				ExtExpiresOn:  internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
				GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
				TokenType:     "Bearer",
			}, cred, "https://fake_authority/dstsv2/"+authority.DSTSTenant)
			if err != nil {
				t.Fatal(err)
			}

			// expect first attempt to fail
			_, err = client.AcquireTokenSilent(context.Background(), tokenScope)
			if err == nil {
				t.Errorf("unexpected nil error from AcquireTokenSilent: %s", err)
			}

			tk, err := client.AcquireTokenByCredential(context.Background(), tokenScope)
			if err != nil {
				t.Errorf("got err == %s, want err == nil", err)
			}
			if tk.AccessToken != token {
				t.Errorf("unexpected access token %s", tk.AccessToken)
			}

			tk, err = client.AcquireTokenSilent(context.Background(), tokenScope)
			if err != nil {
				t.Errorf("got err == %s, want err == nil", err)
			}
			if tk.AccessToken != token {
				t.Errorf("unexpected access token %s", tk.AccessToken)
			}

			// fail for another tenant
			tk, err = client.AcquireTokenSilent(context.Background(), tokenScope, WithTenantID("other"))
			if err == nil {
				t.Errorf("unexpected nil error from AcquireTokenSilent: %s", err)
			}
		})
	}
}
