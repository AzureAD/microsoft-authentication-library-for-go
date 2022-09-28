// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/exported"
	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/fake"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/golang-jwt/jwt/v4"
)

// errorClient is an HTTP client for tests that should fail when confidential.Client sends a request
type errorClient struct{}

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
	fakeClientID      = "fake_client_id"
	fakeTokenEndpoint = "https://fake_authority/fake/token"
	token             = "fake_token"
	refresh           = "fake_refresh"
)

var tokenScope = []string{"the_scope"}

func fakeClient(tk accesstokens.TokenResponse, credential Credential, options ...Option) (Client, error) {
	options = append(options, WithAuthority("https://fake_authority/fake"))
	client, err := New("fake_client_id", credential, options...)
	if err != nil {
		return Client{}, err
	}
	client.base.Token.AccessTokens = &fake.AccessTokens{
		AccessToken: tk,
	}
	client.base.Token.Authority = &fake.Authority{
		InstanceResp: authority.InstanceDiscoveryResponse{
			TenantDiscoveryEndpoint: "https://fake_authority/fake/discovery/endpoint",
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
		Endpoints: authority.NewEndpoints("https://fake_authority/fake/auth",
			fakeTokenEndpoint, "https://fake_authority/fake/jwt", "fake_authority"),
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
			ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
			ExtExpiresOn:  internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
			GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
		}, cred)
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

func TestAcquireTokenByAssertionCallback(t *testing.T) {
	calls := 0
	key := struct{}{}
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
	client, err := fakeClient(accesstokens.TokenResponse{}, cred)
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
	cred, err := NewCredFromSecret("fake_secret")
	if err != nil {
		t.Fatal(err)
	}
	client, err := fakeClient(accesstokens.TokenResponse{
		AccessToken:   token,
		RefreshToken:  refresh,
		ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
		ExtExpiresOn:  internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
		GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
		IDToken: accesstokens.IDToken{
			PreferredUsername: "fakeuser@fakeplace.fake",
			Name:              "fake person",
			Oid:               "123-456",
			TenantID:          "fake",
			Subject:           "nothing",
			Issuer:            "https://fake_authority/fake",
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
			UTID: "fake",
		},
	}, cred)
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
	account := client.Account(tk.Account.HomeAccountID)
	// second attempt should return the cached token
	tk, err = client.AcquireTokenSilent(context.Background(), tokenScope, WithSilentAccount(account))
	if err != nil {
		t.Fatal(err)
	}
	if tk.AccessToken != token {
		t.Fatalf("unexpected access token %s", tk.AccessToken)
	}
}

func TestAcquireTokenWithTenantID(t *testing.T) {
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
		for _, flow := range []string{"authcode", "credential", "obo"} {
			t.Run(flow, func(t *testing.T) {
				cred, err := NewCredFromSecret("secret")
				if err != nil {
					t.Fatal(err)
				}
				idToken, refreshToken := "", ""
				mockClient := mock.Client{}
				if flow == "obo" {
					idToken = "x.e30"
					refreshToken = "refresh-token"
					// TODO: OBO does instance discovery twice before first token request https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/351
					mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, test.tenant)))
				}
				validated := false
				mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, test.tenant)))
				mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, test.tenant)))
				mockClient.AppendResponse(
					mock.WithBody(mock.GetAccessTokenBody("*", idToken, refreshToken, 3600)),
					mock.WithCallback(func(r *http.Request) {
						validated = true
						if u := r.URL.String(); !(strings.HasPrefix(u, test.expectedAuthority) && strings.HasSuffix(u, "/token")) {
							t.Fatalf(`unexpected token request URL "%s"`, u)
						}
					}),
				)
				client, err := New("client-id", cred, WithAuthority(test.authority), WithHTTPClient(&mockClient))
				if err != nil {
					t.Fatal(err)
				}
				ctx := context.Background()
				if _, err = client.AcquireTokenSilent(ctx, tokenScope, WithTenantID(test.tenant)); err == nil {
					t.Fatal("silent auth should fail because the cache is empty")
				}
				switch flow {
				case "authcode":
					_, err = client.AcquireTokenByAuthCode(ctx, "auth code", "https://localhost", tokenScope, WithTenantID(test.tenant))
				case "credential":
					_, err = client.AcquireTokenByCredential(ctx, tokenScope, WithTenantID(test.tenant))
				case "obo":
					_, err = client.AcquireTokenOnBehalfOf(ctx, "assertion", tokenScope, WithTenantID(test.tenant))
				default:
					t.Fatalf("no test for " + flow)
				}
				if err != nil {
					if test.expectError {
						return
					}
					t.Fatal(err)
				} else if !validated {
					t.Fatal("token request validation function wasn't called")
				}
				if flow == "obo" {
					if _, err = client.AcquireTokenOnBehalfOf(ctx, "assertion", tokenScope, WithTenantID(test.tenant)); err != nil {
						t.Fatal(err)
					}
				} else if _, err = client.AcquireTokenSilent(ctx, tokenScope, WithTenantID(test.tenant)); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestInvalidCredential(t *testing.T) {
	data, err := os.ReadFile("../testdata/test-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	certs, key, err := CertFromPEM(data, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, cred := range []Credential{
		{},
		NewCredFromAssertionCallback(nil),
		NewCredFromCert(nil, nil),
		NewCredFromCert(certs[0], nil),
		NewCredFromCert(nil, key),
	} {
		t.Run("", func(t *testing.T) {
			_, err := New("client-id", cred)
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestNewCredFromCertChain(t *testing.T) {
	for _, file := range []struct {
		path     string
		numCerts int
	}{
		{"../testdata/test-cert.pem", 1},
		{"../testdata/test-cert-chain.pem", 2},
		{"../testdata/test-cert-chain-reverse.pem", 2},
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
		cred, err := NewCredFromCertChain(certs, key)
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
					ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(time.Hour)},
					GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
				}, cred, opts...)
				if err != nil {
					t.Fatal(err)
				}
				// the test fake passes assertions generated by the credential to this function
				validated := false
				client.base.Token.AccessTokens.(*fake.AccessTokens).ValidateAssertion = func(s string) {
					validated = true
					tk, err := jwt.Parse(s, func(tk *jwt.Token) (interface{}, error) {
						if signingMethod, ok := tk.Method.(*jwt.SigningMethodRSA); !ok {
							t.Fatalf("unexpected signing method %T", signingMethod)
						}
						return verifyingKey, nil
					})
					if err != nil {
						t.Fatal(err)
					}
					if err = tk.Claims.Valid(); err != nil {
						t.Fatal(err)
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

func TestNewCredFromCertChainError(t *testing.T) {
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
			_, err := NewCredFromCertChain(test.certs, test.key)
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestNewCredFromTokenProvider(t *testing.T) {
	expectedToken := "expected token"
	called := false
	expiresIn := 4200
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
		}, nil
	})
	client, err := New("client-id", cred, WithHTTPClient(&errorClient{}))
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
	if v := int(time.Until(ar.ExpiresOn).Seconds()); v < expiresIn-2 || v > expiresIn {
		t.Fatalf("expected ExpiresOn ~= %d seconds, got %d", expiresIn, v)
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

func TestNewCredFromTokenProviderError(t *testing.T) {
	expectedError := "something went wrong"
	cred := NewCredFromTokenProvider(func(ctx context.Context, tpp exported.TokenProviderParameters) (exported.TokenProviderResult, error) {
		return exported.TokenProviderResult{}, errors.New(expectedError)
	})
	client, err := New("client-id", cred)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AcquireTokenByCredential(context.Background(), tokenScope)
	if err == nil || !strings.Contains(err.Error(), expectedError) {
		t.Fatalf(`unexpected error "%v"`, err)
	}
}
