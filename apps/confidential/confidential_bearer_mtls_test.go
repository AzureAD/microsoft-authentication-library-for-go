// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
)

// assertClientAssertionHasX5C decodes a private_key_jwt client_assertion header and fails unless it
// carries the x5c chain. Bearer-over-mTLS forces x5c on regardless of the app-level WithX5C, mirroring
// MSAL .NET's Mode=OAuth credential resolution.
func assertClientAssertionHasX5C(t *testing.T, assertion string) {
	t.Helper()
	parts := strings.Split(assertion, ".")
	if len(parts) < 2 {
		t.Fatalf("client_assertion is not a JWT: %q", assertion)
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decoding client_assertion JWT header: %v", err)
	}
	if !strings.Contains(string(hdr), "x5c") {
		t.Errorf("client_assertion header must carry x5c for SN/I: %s", hdr)
	}
}

// assertAccessTokenCachedUnder fails unless every access token in the serialized cache is stored under
// wantEnv and none is keyed under an mtlsauth.* host. Bearer-over-mTLS rewrites only the transport
// endpoint (inside accesstokens.doTokenResp), so the cache environment must remain the login-derived
// authority host. This is the deterministic guard against a .NET-style mis-cache under the rewritten
// transport host; the positive check (env == login host) plus the negative check (no "mtlsauth"
// anywhere in the key or environment) locks the transport-vs-cache separation in CI.
func assertAccessTokenCachedUnder(t *testing.T, tc testCache, wantEnv string) {
	t.Helper()
	var found bool
	for _, blob := range tc {
		var root struct {
			AccessToken map[string]struct {
				Environment string `json:"environment"`
			} `json:"AccessToken"`
		}
		if err := json.Unmarshal(blob, &root); err != nil {
			t.Fatalf("unmarshaling cache snapshot: %v", err)
		}
		for key, at := range root.AccessToken {
			found = true
			if at.Environment != wantEnv {
				t.Errorf("access token cached under environment %q, want %q (Bearer-over-mTLS must cache under the login host, not the rewritten mtlsauth host)", at.Environment, wantEnv)
			}
			if strings.Contains(strings.ToLower(key), "mtlsauth") || strings.Contains(strings.ToLower(at.Environment), "mtlsauth") {
				t.Errorf("access token key/environment must not contain mtlsauth (transport host leaked into the cache): key=%q env=%q", key, at.Environment)
			}
		}
	}
	if !found {
		t.Fatal("no access token found in the serialized cache")
	}
}

// TestSendCertificateOverMtls_RequiresCertificateCredential verifies WithSendCertificateOverMtls fails
// fast at construction (New) for credential kinds that cannot present a client certificate on the TLS
// handshake, and succeeds for a certificate credential. Mirrors MSAL .NET's builder Validate
// (InvalidCredentialMaterial) for CertificateOptions.SendCertificateOverMtls.
func TestSendCertificateOverMtls_RequiresCertificateCredential(t *testing.T) {
	certs, key := loadTestCert(t)
	certCred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	secretCred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	assertionCred := NewCredFromAssertionCallback(func(context.Context, AssertionRequestOptions) (string, error) {
		return "assertion", nil
	})
	tokenProviderCred := NewCredFromTokenProvider(func(context.Context, TokenProviderParameters) (TokenProviderResult, error) {
		return TokenProviderResult{AccessToken: "x", ExpiresInSeconds: 3600}, nil
	})

	tests := []struct {
		name    string
		cred    Credential
		wantErr bool
	}{
		{"certificate credential accepted", certCred, false},
		{"secret credential rejected", secretCred, true},
		{"assertion credential rejected", assertionCred, true},
		{"token provider credential rejected", tokenProviderCred, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(fakeAuthority, fakeClientID, test.cred, WithSendCertificateOverMtls())
			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error for a non-certificate credential, got nil")
				}
				if !strings.Contains(err.Error(), "SendCertificateOverMtls") &&
					!strings.Contains(strings.ToLower(err.Error()), "certificate") {
					t.Errorf("error %q should name the flag or the certificate requirement", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for a certificate credential: %v", err)
			}
		})
	}
}

// TestSendCertificateOverMtls_ClientCredential_Global covers Bearer-over-mTLS for the client
// credentials flow with no region: the request is routed to the GLOBAL mtlsauth.microsoft.com
// endpoint over the mutual-TLS transport, carries a private_key_jwt client_assertion (jwt-bearer, with
// x5c forced on), and gets a plain Bearer token back. It must NOT carry token_type=mtls_pop or req_cnf,
// the result must report token_type Bearer with no binding certificate (the token is unbound), and a
// second call is served from the plain Bearer cache.
func TestSendCertificateOverMtls_ClientCredential_Global(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tenant"
	lmo := "login.microsoftonline.com"
	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenant)))

	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(mockClient),
		WithMtlsHTTPClient(func(tls.Certificate) ops.HTTPClient { return mockClient }),
		WithSendCertificateOverMtls(),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	var gotURL *url.URL
	var gotBody url.Values
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody("bearer-over-mtls-token", "", "", "", 3600, 0)),
		mock.WithCallback(func(r *http.Request) {
			gotURL = r.URL
			b, _ := io.ReadAll(r.Body)
			gotBody, _ = url.ParseQuery(string(b))
		}),
	)

	res, err := client.AcquireTokenByCredential(ctx, tokenScope)
	if err != nil {
		t.Fatal(err)
	}

	if gotURL == nil {
		t.Fatal("token endpoint was never called")
	}
	if gotURL.Host != "mtlsauth.microsoft.com" {
		t.Errorf("token endpoint host = %q, want mtlsauth.microsoft.com", gotURL.Host)
	}
	if got := gotBody.Get("grant_type"); got != "client_credentials" {
		t.Errorf("grant_type = %q, want client_credentials", got)
	}
	if got := gotBody.Get("token_type"); got != "" {
		t.Errorf("token_type = %q, want empty (Bearer-over-mTLS must not request mtls_pop)", got)
	}
	if got := gotBody.Get("client_assertion"); got == "" {
		t.Error("Bearer-over-mTLS must send a private_key_jwt client_assertion")
	} else {
		assertClientAssertionHasX5C(t, got)
	}
	if got := gotBody.Get("client_assertion_type"); !strings.Contains(got, "jwt-bearer") {
		t.Errorf("client_assertion_type = %q, want jwt-bearer (not jwt-pop)", got)
	}
	if gotBody.Get("req_cnf") != "" {
		t.Error("Bearer-over-mTLS request must not send req_cnf")
	}

	if res.Metadata.TokenType != "Bearer" {
		t.Errorf("Metadata.TokenType = %q, want Bearer", res.Metadata.TokenType)
	}
	if res.BindingCertificate != nil {
		t.Error("Bearer-over-mTLS token is not bound; BindingCertificate must be nil")
	}

	// Second call is served from the plain Bearer cache.
	res2, err := client.AcquireTokenByCredential(ctx, tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Metadata.TokenSource != TokenSourceCache {
		t.Errorf("second call TokenSource = %d, want cache", res2.Metadata.TokenSource)
	}
	if res2.AccessToken != "bearer-over-mtls-token" {
		t.Errorf("cached AccessToken = %q, want bearer-over-mtls-token", res2.AccessToken)
	}
}

// TestSendCertificateOverMtls_MtlsPoPTakesPrecedence verifies a per-request WithMtlsProofOfPossession
// always wins over the app-level WithSendCertificateOverMtls: the request is a real mtls_pop request
// (token_type=mtls_pop, pure-certificate, no client_assertion), not a Bearer-over-mTLS request.
func TestSendCertificateOverMtls_MtlsPoPTakesPrecedence(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tenant"
	lmo := "login.microsoftonline.com"
	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenant)))

	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(mockClient),
		WithMtlsHTTPClient(func(tls.Certificate) ops.HTTPClient { return mockClient }),
		WithSendCertificateOverMtls(),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	var gotBody url.Values
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mtlsPoPTokenBody("mtls-pop-token", 3600)),
		mock.WithCallback(func(r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			gotBody, _ = url.ParseQuery(string(b))
		}),
	)

	res, err := client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}
	if got := gotBody.Get("token_type"); got != "mtls_pop" {
		t.Errorf("token_type = %q, want mtls_pop (per-request PoP must win over the app flag)", got)
	}
	if gotBody.Get("client_assertion") != "" {
		t.Error("pure-cert mtls_pop request must not send client_assertion")
	}
	if res.Metadata.TokenType != "mtls_pop" {
		t.Errorf("Metadata.TokenType = %q, want mtls_pop", res.Metadata.TokenType)
	}
}

// TestSendCertificateOverMtls_ClientCredential_Regional verifies that when a region is configured the
// Bearer-over-mTLS request is routed to the regional mtlsauth endpoint ({region}.mtlsauth.microsoft.com)
// while still returning a plain Bearer token with a client_assertion and no token_type=mtls_pop.
func TestSendCertificateOverMtls_ClientCredential_Regional(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tenant"
	lmo := "login.microsoftonline.com"
	region := "westus3"
	mockClient := mock.NewClient()

	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(mockClient),
		WithMtlsHTTPClient(func(tls.Certificate) ops.HTTPClient { return mockClient }),
		WithSendCertificateOverMtls(),
		WithAzureRegion(region),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	var gotURL *url.URL
	var gotBody url.Values
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody("bearer-over-mtls-token", "", "", "", 3600, 0)),
		mock.WithCallback(func(r *http.Request) {
			gotURL = r.URL
			b, _ := io.ReadAll(r.Body)
			gotBody, _ = url.ParseQuery(string(b))
		}),
	)

	if _, err := client.AcquireTokenByCredential(ctx, tokenScope); err != nil {
		t.Fatal(err)
	}
	if gotURL == nil {
		t.Fatal("token endpoint was never called")
	}
	if want := region + ".mtlsauth.microsoft.com"; gotURL.Host != want {
		t.Errorf("token endpoint host = %q, want %s", gotURL.Host, want)
	}
	if got := gotBody.Get("token_type"); got != "" {
		t.Errorf("token_type = %q, want empty (Bearer-over-mTLS must not request mtls_pop)", got)
	}
	if got := gotBody.Get("client_assertion"); got == "" {
		t.Error("Bearer-over-mTLS must send a private_key_jwt client_assertion")
	} else {
		assertClientAssertionHasX5C(t, got)
	}
}

// TestSendCertificateOverMtls_OnBehalfOf_Global verifies the app-level flag routes an on-behalf-of
// request over the global mtlsauth endpoint, returns a plain Bearer token (no token_type=mtls_pop,
// unbound), and that a second call is served from the plain Bearer cache without crashing on the
// rewritten mtlsauth environment (metadata must key off the original login.* authority).
func TestSendCertificateOverMtls_OnBehalfOf_Global(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tenant"
	lmo := "login.microsoftonline.com"
	assertion := "user-assertion"
	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenant)))

	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(mockClient),
		WithMtlsHTTPClient(func(tls.Certificate) ops.HTTPClient { return mockClient }),
		WithSendCertificateOverMtls(),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	var gotURL *url.URL
	var gotBody url.Values
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody("obo-bearer-token", "", "rt", "", 3600, 0)),
		mock.WithCallback(func(r *http.Request) {
			gotURL = r.URL
			b, _ := io.ReadAll(r.Body)
			gotBody, _ = url.ParseQuery(string(b))
		}),
	)

	res, err := client.AcquireTokenOnBehalfOf(ctx, assertion, tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if gotURL == nil {
		t.Fatal("token endpoint was never called")
	}
	if gotURL.Host != "mtlsauth.microsoft.com" {
		t.Errorf("token endpoint host = %q, want mtlsauth.microsoft.com", gotURL.Host)
	}
	if got := gotBody.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Errorf("grant_type = %q, want jwt-bearer (OBO)", got)
	}
	if got := gotBody.Get("requested_token_use"); got != "on_behalf_of" {
		t.Errorf("requested_token_use = %q, want on_behalf_of", got)
	}
	if got := gotBody.Get("assertion"); got != assertion {
		t.Errorf("assertion = %q, want %q", got, assertion)
	}
	if got := gotBody.Get("token_type"); got != "" {
		t.Errorf("token_type = %q, want empty (Bearer-over-mTLS)", got)
	}
	if got := gotBody.Get("client_assertion"); got == "" {
		t.Error("Bearer-over-mTLS OBO must send a private_key_jwt client_assertion")
	} else {
		assertClientAssertionHasX5C(t, got)
	}
	if res.Metadata.TokenType != "Bearer" {
		t.Errorf("Metadata.TokenType = %q, want Bearer", res.Metadata.TokenType)
	}
	if res.BindingCertificate != nil {
		t.Error("Bearer-over-mTLS token is not bound; BindingCertificate must be nil")
	}

	res2, err := client.AcquireTokenOnBehalfOf(ctx, assertion, tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Metadata.TokenSource != TokenSourceCache {
		t.Errorf("second OBO call TokenSource = %d, want cache", res2.Metadata.TokenSource)
	}
	if res2.AccessToken != "obo-bearer-token" {
		t.Errorf("cached AccessToken = %q, want obo-bearer-token", res2.AccessToken)
	}
}

// TestSendCertificateOverMtls_OnBehalfOf_Regional verifies the flag routes OBO to the regional mtlsauth
// endpoint when a region is configured.
func TestSendCertificateOverMtls_OnBehalfOf_Regional(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tenant"
	lmo := "login.microsoftonline.com"
	region := "westus3"
	assertion := "user-assertion"
	mockClient := mock.NewClient()

	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(mockClient),
		WithMtlsHTTPClient(func(tls.Certificate) ops.HTTPClient { return mockClient }),
		WithSendCertificateOverMtls(),
		WithAzureRegion(region),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	var gotURL *url.URL
	var gotBody url.Values
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody("obo-bearer-token", "", "rt", "", 3600, 0)),
		mock.WithCallback(func(r *http.Request) {
			gotURL = r.URL
			b, _ := io.ReadAll(r.Body)
			gotBody, _ = url.ParseQuery(string(b))
		}),
	)

	if _, err := client.AcquireTokenOnBehalfOf(ctx, assertion, tokenScope); err != nil {
		t.Fatal(err)
	}
	if gotURL == nil {
		t.Fatal("token endpoint was never called")
	}
	if want := region + ".mtlsauth.microsoft.com"; gotURL.Host != want {
		t.Errorf("token endpoint host = %q, want %s", gotURL.Host, want)
	}
	if got := gotBody.Get("token_type"); got != "" {
		t.Errorf("token_type = %q, want empty (Bearer-over-mTLS)", got)
	}
	if got := gotBody.Get("client_assertion"); got == "" {
		t.Error("Bearer-over-mTLS OBO must send a private_key_jwt client_assertion")
	} else {
		assertClientAssertionHasX5C(t, got)
	}
}

// TestSendCertificateOverMtls_AuthCode_Global verifies the flag routes an authorization-code redemption
// over the global mtlsauth endpoint with a plain Bearer result and a forced-x5c client_assertion.
func TestSendCertificateOverMtls_AuthCode_Global(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tenant"
	lmo := "login.microsoftonline.com"
	mockClient := mock.NewClient()

	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(mockClient),
		WithMtlsHTTPClient(func(tls.Certificate) ops.HTTPClient { return mockClient }),
		WithSendCertificateOverMtls(),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	var gotURL *url.URL
	var gotBody url.Values
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody("authcode-bearer-token", "", "", "", 3600, 0)),
		mock.WithCallback(func(r *http.Request) {
			gotURL = r.URL
			b, _ := io.ReadAll(r.Body)
			gotBody, _ = url.ParseQuery(string(b))
		}),
	)

	res, err := client.AcquireTokenByAuthCode(ctx, "auth-code", "https://localhost", tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if gotURL == nil {
		t.Fatal("token endpoint was never called")
	}
	if gotURL.Host != "mtlsauth.microsoft.com" {
		t.Errorf("token endpoint host = %q, want mtlsauth.microsoft.com", gotURL.Host)
	}
	if got := gotBody.Get("grant_type"); got != "authorization_code" {
		t.Errorf("grant_type = %q, want authorization_code", got)
	}
	if got := gotBody.Get("code"); got != "auth-code" {
		t.Errorf("code = %q, want auth-code", got)
	}
	if got := gotBody.Get("token_type"); got != "" {
		t.Errorf("token_type = %q, want empty (Bearer-over-mTLS)", got)
	}
	if got := gotBody.Get("client_assertion"); got == "" {
		t.Error("Bearer-over-mTLS auth-code must send a private_key_jwt client_assertion")
	} else {
		assertClientAssertionHasX5C(t, got)
	}
	if res.Metadata.TokenType != "Bearer" {
		t.Errorf("Metadata.TokenType = %q, want Bearer", res.Metadata.TokenType)
	}
	if res.BindingCertificate != nil {
		t.Error("Bearer-over-mTLS token is not bound; BindingCertificate must be nil")
	}
}

// TestSendCertificateOverMtls_RefreshViaSilent verifies a refresh triggered from AcquireTokenSilent under
// the flag routes over mtlsauth with grant_type=refresh_token and returns a plain Bearer token. msal-go
// has no public refresh entrypoint; refresh is exercised through the silent path. This also guards the
// second-call regression: instance/tenant metadata must resolve against the original login.* authority,
// not the rewritten mtlsauth host.
func TestSendCertificateOverMtls_RefreshViaSilent(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tenant"
	lmo := "login.microsoftonline.com"
	clientInfo := base64.RawStdEncoding.EncodeToString([]byte(`{"uid":"uid","utid":"utid"}`))
	idToken := mock.GetIDToken(tenant, fmt.Sprintf(authorityFmt, lmo, tenant))
	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	// Seed a short-lived access token: storage treats it as expired (5-minute skew), so the next silent
	// call redeems the cached refresh token rather than re-acquiring via client_credentials.
	mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody("at-1", idToken, "rt", clientInfo, 1, 0)))

	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(mockClient),
		WithMtlsHTTPClient(func(tls.Certificate) ops.HTTPClient { return mockClient }),
		WithSendCertificateOverMtls(),
		WithInstanceDiscovery(false),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	ar, err := client.AcquireTokenByAuthCode(ctx, "auth-code", "https://localhost", tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if ar.AccessToken != "at-1" {
		t.Fatalf("seed AccessToken = %q, want at-1", ar.AccessToken)
	}
	account := ar.Account

	var gotURL *url.URL
	var gotBody url.Values
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody("at-2", idToken, "rt", clientInfo, 3600, 0)),
		mock.WithCallback(func(r *http.Request) {
			gotURL = r.URL
			b, _ := io.ReadAll(r.Body)
			gotBody, _ = url.ParseQuery(string(b))
		}),
	)

	ar, err = client.AcquireTokenSilent(ctx, tokenScope, WithSilentAccount(account))
	if err != nil {
		t.Fatal(err)
	}
	if gotURL == nil {
		t.Fatal("refresh token endpoint was never called")
	}
	if gotURL.Host != "mtlsauth.microsoft.com" {
		t.Errorf("refresh endpoint host = %q, want mtlsauth.microsoft.com", gotURL.Host)
	}
	if got := gotBody.Get("grant_type"); got != "refresh_token" {
		t.Errorf("grant_type = %q, want refresh_token", got)
	}
	if got := gotBody.Get("refresh_token"); got != "rt" {
		t.Errorf("refresh_token = %q, want rt", got)
	}
	if got := gotBody.Get("token_type"); got != "" {
		t.Errorf("token_type = %q, want empty (Bearer-over-mTLS)", got)
	}
	if got := gotBody.Get("client_assertion"); got == "" {
		t.Error("Bearer-over-mTLS refresh must send a private_key_jwt client_assertion")
	} else {
		assertClientAssertionHasX5C(t, got)
	}
	if ar.AccessToken != "at-2" {
		t.Errorf("refreshed AccessToken = %q, want at-2", ar.AccessToken)
	}
	if ar.Metadata.TokenSource != base.TokenSourceIdentityProvider {
		t.Errorf("refreshed TokenSource = %d, want identity provider", ar.Metadata.TokenSource)
	}
}

// TestSendCertificateOverMtls_OnBehalfOf_NoFlag is the negative control: without the app-level flag an
// OBO request goes to the regular login endpoint, never the mtlsauth transport.
func TestSendCertificateOverMtls_OnBehalfOf_NoFlag(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tenant"
	lmo := "login.microsoftonline.com"
	assertion := "user-assertion"
	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenant)))

	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(mockClient),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	var gotURL *url.URL
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody("plain-token", "", "rt", "", 3600, 0)),
		mock.WithCallback(func(r *http.Request) { gotURL = r.URL }),
	)

	if _, err := client.AcquireTokenOnBehalfOf(ctx, assertion, tokenScope); err != nil {
		t.Fatal(err)
	}
	if gotURL == nil {
		t.Fatal("token endpoint was never called")
	}
	if gotURL.Host != lmo {
		t.Errorf("token endpoint host = %q, want %s (no flag → regular endpoint)", gotURL.Host, lmo)
	}
}

// TestSendCertificateOverMtls_ClientCredential_CachesUnderLoginHost locks the transport-vs-cache
// separation for Bearer-over-mTLS: the mtlsauth rewrite is a transport-only concern, so the access
// token must be cached under the ORIGINAL login.* authority environment, never under the rewritten
// mtlsauth host. Instance discovery is deliberately left ON so the second call exercises the
// metadata-resolution path where MSAL .NET's second-call regression lived (feeding the rewritten host
// into region/instance discovery). A token mis-cached under mtlsauth would both fail the negative
// environment assertion here and crash that path in the regional live cell; a discovery-OFF test would
// short-circuit it and catch neither. Mirrors the deterministic cache-env guard the sibling SDKs adopted.
func TestSendCertificateOverMtls_ClientCredential_CachesUnderLoginHost(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tenant"
	lmo := "login.microsoftonline.com"
	tc := make(testCache)
	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenant)))

	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(mockClient),
		WithMtlsHTTPClient(func(tls.Certificate) ops.HTTPClient { return mockClient }),
		WithSendCertificateOverMtls(),
		WithCache(&tc),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody("bom-token", "", "", "", 3600, 0)))

	res, err := client.AcquireTokenByCredential(ctx, tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if res.Metadata.TokenType != "Bearer" {
		t.Errorf("Metadata.TokenType = %q, want Bearer", res.Metadata.TokenType)
	}

	// The access token must be cached under the login-derived environment, NOT the rewritten mtlsauth
	// host. This negative assertion is what deterministically catches a .NET-style mis-cache.
	assertAccessTokenCachedUnder(t, tc, lmo)

	// The second call must be served from that cache. No further HTTP responses are queued, so a cache
	// miss (e.g. because the token was keyed under the wrong environment) would fail with an exhausted
	// mock rather than silently pass.
	res2, err := client.AcquireTokenByCredential(ctx, tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Metadata.TokenSource != TokenSourceCache {
		t.Errorf("second call TokenSource = %d, want cache", res2.Metadata.TokenSource)
	}
	if res2.AccessToken != "bom-token" {
		t.Errorf("cached AccessToken = %q, want bom-token", res2.AccessToken)
	}
}
