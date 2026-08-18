// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

// newBindingCertCred builds a self-signed certificate credential. Two calls produce two certificates
// with different SHA-256 thumbprints, i.e. two different x5t#S256 key IDs.
func newBindingCertCred(t *testing.T, commonName string, serial int64) Credential {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := NewCredFromCert([]*x509.Certificate{leaf}, crypto.PrivateKey(key))
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

// TestMtlsPoPTwoCertificatesShareACacheWithoutConfusion is the evidence for declining to add the
// binding certificate's thumbprint to the access-token cache WRITE key.
//
// The concern was that two binding certificates for the same client, tenant and scope collide in the
// cache and one certificate's token gets served for the other. They do share a write key - and that
// is fine, because the thumbprint is applied as a READ filter: readAccessToken compares the request's
// authentication-scheme key ID (x5t#S256) against the cached entry's AuthnSchemeKeyID
// (storage.go and partitioned_storage.go). A request bound to a different certificate therefore
// MISSES and goes to the identity provider; it never receives the other certificate's token.
//
// MSAL .NET behaves the same way; its analogue is
// MtlsPop_SameKeyCertRenewal_MustNotServeStaleCachedTokenAsync in MtlsPopTests.
//
// This test shares one cache between two clients that differ only in their binding certificate. The
// mock panics when its response queue is empty, so a call that is expected to hit the cache is proven
// by consuming no queued response, and a call that is expected to miss is proven by consuming one.
//
// Note what the test also documents: because the write key collides, the second certificate's token
// REPLACES the first's. The read filter guarantees correctness, not coexistence - alternating
// certificates costs a cache miss each time. That is the same shape .NET depends on for certificate
// renewal, and it is a performance characteristic rather than a correctness problem.
func TestMtlsPoPTwoCertificatesShareACacheWithoutConfusion(t *testing.T) {
	credA := newBindingCertCred(t, "binding-cert-a", 1)
	credB := newBindingCertCred(t, "binding-cert-b", 2)

	lmo := "login.microsoftonline.com"
	tenant := "tenant"
	authority := fmt.Sprintf(authorityFmt, lmo, tenant)
	sharedCache := make(testCache)
	mockClient := mock.NewClient()
	ctx := context.Background()

	newClient := func(cred Credential) Client {
		t.Helper()
		client, err := New(authority, fakeClientID, cred,
			WithCache(&sharedCache),
			WithHTTPClient(mockClient),
			WithMtlsHTTPClient(mockMtlsFactory(mockClient)),
			WithInstanceDiscovery(false),
		)
		if err != nil {
			t.Fatal(err)
		}
		return client
	}

	clientA := newClient(credA)
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(mock.WithBody(mtlsPoPTokenBody("token-for-cert-a", 3600)))

	resA, err := clientA.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}
	if resA.AccessToken != "token-for-cert-a" {
		t.Fatalf("first call returned %q, want token-for-cert-a", resA.AccessToken)
	}
	if resA.Metadata.TokenSource != TokenSourceIdentityProvider {
		t.Fatal("first call should have gone to the identity provider")
	}

	// Same certificate, same everything: this must be served from the cache. No response is queued,
	// so a miss would panic the mock rather than quietly pass.
	cachedA, err := clientA.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}
	if cachedA.Metadata.TokenSource != TokenSourceCache || cachedA.AccessToken != resA.AccessToken {
		t.Fatalf("same-certificate repeat call was not served from the cache: source=%v token=%q",
			cachedA.Metadata.TokenSource, cachedA.AccessToken)
	}

	// Different binding certificate, same client/tenant/scope and the SAME cache. The write key
	// collides; the read filter must still refuse cert A's token.
	clientB := newClient(credB)
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(mock.WithBody(mtlsPoPTokenBody("token-for-cert-b", 3600)))

	resB, err := clientB.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}
	if resB.Metadata.TokenSource != TokenSourceIdentityProvider {
		t.Fatal("a request bound to a different certificate must MISS the cache, not reuse the other certificate's token")
	}
	if resB.AccessToken == resA.AccessToken {
		t.Fatal("the second certificate was served the first certificate's token; the read filter is not working")
	}
	if resB.AccessToken != "token-for-cert-b" {
		t.Fatalf("second certificate returned %q, want token-for-cert-b", resB.AccessToken)
	}
	if resA.BindingCertificateThumbprint() == resB.BindingCertificateThumbprint() {
		t.Fatal("the two credentials produced the same thumbprint; the test proves nothing")
	}

	// Both entries share a write key, so cert B's acquisition OVERWROTE cert A's entry rather than
	// sitting beside it. That is the behavior to document: the read filter buys correctness, not
	// coexistence. Cert A therefore MISSES and re-acquires - the important part being that it is
	// never handed cert B's token. MSAL .NET relies on exactly this for certificate renewal
	// (MtlsPop_SameKeyCertRenewal_MustNotServeStaleCachedTokenAsync): the new certificate's write
	// displaces the old token, and the read filter keeps the stale one from being served in the
	// meantime.
	mockClient.AppendResponse(mock.WithBody(mtlsPoPTokenBody("token-for-cert-a-again", 3600)))
	reacquiredA, err := clientA.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}
	if reacquiredA.AccessToken == resB.AccessToken {
		t.Fatal("cert A was served cert B's token; the read filter is not working")
	}
	if reacquiredA.Metadata.TokenSource != TokenSourceIdentityProvider {
		t.Fatal("cert A should have missed the cache after cert B's write and re-acquired")
	}
	if reacquiredA.AccessToken != "token-for-cert-a-again" {
		t.Fatalf("cert A re-acquired %q, want token-for-cert-a-again", reacquiredA.AccessToken)
	}
}

// countingRoundTripper serves a canned token response and counts token-endpoint requests.
type countingRoundTripper struct {
	tokenCalls int32
	body       string
}

func (rt *countingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&rt.tokenCalls, 1)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       nopCloser{strings.NewReader(rt.body)},
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Request:    req,
	}, nil
}

func (rt *countingRoundTripper) count() int { return int(atomic.LoadInt32(&rt.tokenCalls)) }

type nopCloser struct{ *strings.Reader }

func (nopCloser) Close() error { return nil }

// TestMtlsPoPDowngradedTokenIsNotCached covers the token_type downgrade through the PUBLIC
// acquisition pipeline. There is already a low-level test that FromClientCertificate errors when the
// response says Bearer, but that one bypasses the cache entirely, so on its own it cannot show what
// happens to the bad response afterwards.
//
// The requirement is fail-closed AND no poisoning: the downgraded response must not be written to the
// cache, so a second identical call has to reach the token endpoint again and fail again rather than
// quietly serving a Bearer token to a caller who asked for proof-of-possession. The token-endpoint
// request count is the mechanism: it must be 2 after two calls.
func TestMtlsPoPDowngradedTokenIsNotCached(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}

	lmo := "login.microsoftonline.com"
	tenant := "tenant"
	mockClient := mock.NewClient()

	// The token endpoint answers over the mTLS transport, so the downgrade is injected there.
	downgraded := &countingRoundTripper{
		body: fmt.Sprintf(
			`{"access_token":"downgraded-token","expires_in":3600,"expires_on":%d,"token_type":"Bearer"}`,
			time.Now().Add(time.Hour).Unix(),
		),
	}

	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(mockClient),
		WithMtlsHTTPClient(func(tls.Certificate) *http.Client {
			return &http.Client{Transport: downgraded}
		}),
		WithInstanceDiscovery(false),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	_, err = client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("a Bearer response to an mTLS PoP request must fail closed, got nil error")
	}
	if !strings.Contains(err.Error(), "mtls_pop") {
		t.Errorf("error = %q, want it to report the mtls_pop token type mismatch", err)
	}
	if n := downgraded.count(); n != 1 {
		t.Fatalf("token endpoint called %d time(s) on the first acquisition, want 1", n)
	}

	// Second identical call. If the downgraded response had been cached, this would be served from
	// the cache without touching the token endpoint - and would hand back a Bearer token.
	_, err = client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("the second call must fail closed too, got nil error")
	}
	if n := downgraded.count(); n != 2 {
		t.Fatalf("token endpoint called %d time(s) in total, want 2; the downgraded response was cached", n)
	}
}
