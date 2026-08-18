// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
)

func loadTestCert(t *testing.T) ([]*x509.Certificate, crypto.PrivateKey) {
	t.Helper()
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
		t.Fatal(err)
	}
	return certs, key
}

func mtlsPoPTokenBody(accessToken string, expiresIn int) []byte {
	return []byte(fmt.Sprintf(
		`{"access_token":"%s","expires_in":%d,"expires_on":%d,"token_type":"mtls_pop"}`,
		accessToken, expiresIn, time.Now().Add(time.Duration(expiresIn)*time.Second).Unix(),
	))
}

// mockRoundTripper adapts a mock HTTP client to http.RoundTripper so tests can install it through the
// public WithMtlsHTTPClient option, which takes a concrete *http.Client rather than an internal
// interface. Going through the public option keeps these tests on exactly the code path an external
// consumer uses.
type mockRoundTripper struct{ client *mock.Client }

func (rt mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.client.Do(req)
}

// mockMtlsFactory returns a factory in the public WithMtlsHTTPClient shape that routes every mTLS
// token request to the supplied mock.
func mockMtlsFactory(c *mock.Client) func(tls.Certificate) *http.Client {
	return func(tls.Certificate) *http.Client {
		return &http.Client{Transport: mockRoundTripper{client: c}}
	}
}

// TestAcquireTokenByCredentialMtlsPoP covers Scope 1 (vanilla SNI -> mTLS PoP): the request is
// routed to the rewritten mtlsauth endpoint, carries token_type=mtls_pop with no client_assertion
// and no req_cnf, the result reports the mtls_pop token type and public binding certificate, and a
// second call is served from the cache.
func TestAcquireTokenByCredentialMtlsPoP(t *testing.T) {
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
		WithMtlsHTTPClient(mockMtlsFactory(mockClient)),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	var gotURL *url.URL
	var gotBody url.Values
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mtlsPoPTokenBody("mtls-access-token", 3600)),
		mock.WithCallback(func(r *http.Request) {
			gotURL = r.URL
			b, _ := io.ReadAll(r.Body)
			gotBody, _ = url.ParseQuery(string(b))
		}),
	)

	res, err := client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}

	if gotURL == nil {
		t.Fatal("token endpoint was never called")
	}
	if gotURL.Host != "mtlsauth.microsoft.com" {
		t.Errorf("token endpoint host = %q, want mtlsauth.microsoft.com", gotURL.Host)
	}
	if got := gotBody.Get("token_type"); got != "mtls_pop" {
		t.Errorf("token_type = %q, want mtls_pop", got)
	}
	if got := gotBody.Get("grant_type"); got != "client_credentials" {
		t.Errorf("grant_type = %q, want client_credentials", got)
	}
	if gotBody.Get("client_assertion") != "" {
		t.Error("pure-cert mTLS request must not send client_assertion")
	}
	if gotBody.Get("req_cnf") != "" {
		t.Error("mTLS PoP request must not send req_cnf")
	}

	if res.Metadata.TokenType != "mtls_pop" {
		t.Errorf("Metadata.TokenType = %q, want mtls_pop", res.Metadata.TokenType)
	}
	if res.BindingCertificate == nil {
		t.Fatal("BindingCertificate is nil, want the bound client certificate")
	}
	if res.BindingCertificate.Leaf == nil {
		t.Fatal("BindingCertificate.Leaf is nil, want the parsed leaf certificate")
	}
	if res.BindingCertificate.Leaf.Raw == nil || res.BindingCertificate.Leaf.PublicKey == nil {
		t.Error("BindingCertificate is not a usable public certificate")
	}
	if res.BindingCertificate.PrivateKey == nil {
		t.Error("BindingCertificate.PrivateKey is nil, so the caller cannot present it on the TLS handshake")
	}
	sum := sha256.Sum256(certs[0].Raw)
	wantThumb := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := res.BindingCertificateThumbprint(); got != wantThumb {
		t.Errorf("BindingCertificateThumbprint = %q, want %q", got, wantThumb)
	}

	// Second call is served from the cache and still carries the mTLS PoP metadata.
	res2, err := client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}
	if res2.Metadata.TokenSource != TokenSourceCache {
		t.Errorf("second call TokenSource = %d, want cache", res2.Metadata.TokenSource)
	}
	if res2.AccessToken != "mtls-access-token" {
		t.Errorf("cached AccessToken = %q, want mtls-access-token", res2.AccessToken)
	}
	if res2.BindingCertificate == nil {
		t.Fatal("cached result BindingCertificate is nil, want the bound client certificate")
	}
	// base.go populates the binding certificate on the cache-hit path too; a caller that gets a cached
	// token must still be able to present the certificate to the resource.
	if res2.BindingCertificate.Leaf == nil {
		t.Error("cached result BindingCertificate.Leaf is nil, want the parsed leaf certificate")
	}
	if res2.BindingCertificate.PrivateKey == nil {
		t.Error("cached result BindingCertificate.PrivateKey is nil, so the caller cannot present it on the TLS handshake")
	}
	if got := res2.BindingCertificateThumbprint(); got != wantThumb {
		t.Errorf("cached BindingCertificateThumbprint = %q, want %q", got, wantThumb)
	}
}

// TestMtlsPoPCredentialValidation verifies that mTLS PoP fails fast for credential kinds that can't
// present a client certificate, before any network call.
func TestMtlsPoPCredentialValidation(t *testing.T) {
	ctx := context.Background()

	t.Run("client secret rejected", func(t *testing.T) {
		cred, err := NewCredFromSecret(fakeSecret)
		if err != nil {
			t.Fatal(err)
		}
		client, err := fakeClient(accesstokens.TokenResponse{}, cred, fakeAuthority)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession()); err == nil {
			t.Error("expected error for secret credential + mTLS PoP")
		}
	})

	t.Run("token provider rejected", func(t *testing.T) {
		cred := NewCredFromTokenProvider(func(context.Context, TokenProviderParameters) (TokenProviderResult, error) {
			return TokenProviderResult{AccessToken: "x", ExpiresInSeconds: 3600}, nil
		})
		client, err := New(fakeAuthority, fakeClientID, cred)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession()); err == nil {
			t.Error("expected error for token-provider credential + mTLS PoP")
		}
	})

	t.Run("assertion credential rejected", func(t *testing.T) {
		cred := NewCredFromAssertionCallback(func(context.Context, AssertionRequestOptions) (string, error) {
			return "assertion", nil
		})
		client, err := fakeClient(accesstokens.TokenResponse{}, cred, fakeAuthority)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession()); err == nil {
			t.Error("expected error for assertion credential + mTLS PoP")
		}
	})
}
