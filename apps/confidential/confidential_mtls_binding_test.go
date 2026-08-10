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
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
)

// testCertThumbprint is the x5t#S256 that BindingCertificateThumbprint() emits for
// apps/testdata/test-cert.pem. It was captured from the implementation as it stood *before*
// AuthResult.BindingCertificate changed from *x509.Certificate to *tls.Certificate, so it pins the
// new Leaf-based computation to byte-identical output. The thumbprint is a public certificate hash,
// not a secret; it also lands in cache keys and in the token's cnf claim, so it must never drift.
const testCertThumbprint = "FSGtWRhyFt0jB9L_Xi72L8bEiBEqPP7ZDYKygYl-qRA"

// mtlsPoPTestClient wires a confidential client whose token endpoint and mTLS transport are both the
// supplied mock, and primes instance/tenant discovery plus one mtls_pop token response.
func mtlsPoPTestClient(t *testing.T, cred Credential) (Client, *mock.Client) {
	t.Helper()
	tenant := "tenant"
	lmo := "login.microsoftonline.com"
	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenant)))
	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(mockClient),
		WithMtlsHTTPClient(func(tls.Certificate) ops.HTTPClient { return mockClient }),
	)
	if err != nil {
		t.Fatal(err)
	}
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(mock.WithBody(mtlsPoPTokenBody("mtls-access-token", 3600)))
	return client, mockClient
}

// TestMtlsPoPBindingCertificateIsUsableForTLS is the core regression guard for the defect this change
// fixes: AuthResult.BindingCertificate used to be an *x509.Certificate, i.e. public material only, so
// the documented "present it as the client certificate on the TLS handshake" was impossible. The
// result must now be a tls.Certificate that carries both the parsed leaf and the private key, and it
// must be directly loadable into a tls.Config. It also pins the thumbprint against a golden value so
// the type change cannot silently alter x5t#S256.
func TestMtlsPoPBindingCertificateIsUsableForTLS(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := mtlsPoPTestClient(t, cred)
	ctx := context.Background()

	res, err := client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}

	if res.BindingCertificate == nil {
		t.Fatal("BindingCertificate is nil")
	}
	if res.BindingCertificate.Leaf == nil {
		t.Fatal("BindingCertificate.Leaf is nil; callers cannot inspect the bound certificate")
	}
	if !res.BindingCertificate.Leaf.Equal(certs[0]) {
		t.Error("BindingCertificate.Leaf is not the credential's signing certificate")
	}
	if res.BindingCertificate.PrivateKey == nil {
		t.Fatal("BindingCertificate.PrivateKey is nil; the certificate cannot be presented on a TLS handshake")
	}
	if res.BindingCertificate.PrivateKey != key {
		t.Error("BindingCertificate.PrivateKey is not the key the token was bound with")
	}
	if len(res.BindingCertificate.Certificate) == 0 {
		t.Fatal("BindingCertificate carries no DER chain")
	}

	// The whole point of the type change: the value drops straight into a tls.Config. Building the
	// config is enough to prove the certificate is well-formed for crypto/tls.
	cfg := &tls.Config{
		Certificates: []tls.Certificate{*res.BindingCertificate},
		MinVersion:   tls.VersionTLS12,
	}
	if _, err := cfg.Certificates[0].Leaf.Verify(x509.VerifyOptions{
		Roots:       rootsFor(certs[0]),
		CurrentTime: certs[0].NotBefore.Add(time.Minute),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("binding certificate does not verify against itself: %s", err)
	}

	if got := res.BindingCertificateThumbprint(); got != testCertThumbprint {
		t.Errorf("BindingCertificateThumbprint() = %q, want %q (the pre-change value; x5t#S256 must not drift)", got, testCertThumbprint)
	}
}

// TestMtlsPoPBindingCertificateOnCacheHit covers the cached branch in base.AcquireTokenSilent, which
// populates BindingCertificate separately from the token-response path. A caller served from the
// cache still has to be able to call the resource, so the private key must be present there too.
func TestMtlsPoPBindingCertificateOnCacheHit(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := mtlsPoPTestClient(t, cred)
	ctx := context.Background()

	if _, err := client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession()); err != nil {
		t.Fatal(err)
	}
	// No further mock responses are queued, so this call can only be served from the cache.
	cached, err := client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}
	if cached.Metadata.TokenSource != TokenSourceCache {
		t.Fatalf("TokenSource = %d, want cache", cached.Metadata.TokenSource)
	}
	if cached.BindingCertificate == nil {
		t.Fatal("cached result has no BindingCertificate")
	}
	if cached.BindingCertificate.Leaf == nil {
		t.Error("cached BindingCertificate.Leaf is nil")
	}
	if cached.BindingCertificate.PrivateKey == nil {
		t.Fatal("cached BindingCertificate.PrivateKey is nil; a cache hit must still be usable against the resource")
	}
	if got := cached.BindingCertificateThumbprint(); got != testCertThumbprint {
		t.Errorf("cached BindingCertificateThumbprint() = %q, want %q", got, testCertThumbprint)
	}
}

// opaqueSigner wraps a key behind crypto.Signer only, so it is deliberately NOT type-assertable to
// *rsa.PrivateKey. It models a non-exportable platform key (Windows KeyGuard, CNG, an HSM): the
// private material never leaves the key store, and only Sign is reachable. crypto/tls needs nothing
// more than a crypto.Signer, so such a key is a valid tls.Certificate.PrivateKey.
type opaqueSigner struct{ inner *rsa.PrivateKey }

func (s opaqueSigner) Public() crypto.PublicKey { return s.inner.Public() }

func (s opaqueSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.inner.Sign(r, digest, opts)
}

// TestMtlsPoPBindingCertificateKeepsOpaqueSigner proves the fix is not merely "an *rsa.PrivateKey now
// comes back": an opaque, non-exportable signer must survive the AuthResult boundary as a
// crypto.Signer. This is the KeyGuard scenario, where the caller can never rebuild the
// tls.Certificate themselves because they have no key bytes to supply.
//
// The credential is constructed directly rather than through NewCredFromCert, which currently
// requires a concrete *rsa.PrivateKey. That restriction is out of scope here; this test covers the
// AuthResult side of the boundary so a signer-backed credential works the moment one can be created.
func TestMtlsPoPBindingCertificateKeepsOpaqueSigner(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "keyguard-style-binding-cert"},
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

	signer := opaqueSigner{inner: key}
	cred := Credential{cert: leaf, key: signer, x5c: []string{base64.StdEncoding.EncodeToString(der)}}
	client, _ := mtlsPoPTestClient(t, cred)

	res, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}
	if res.BindingCertificate == nil || res.BindingCertificate.PrivateKey == nil {
		t.Fatal("the opaque signer did not survive: BindingCertificate has no private key")
	}
	if _, ok := res.BindingCertificate.PrivateKey.(*rsa.PrivateKey); ok {
		t.Fatal("the test signer must not be assertable to *rsa.PrivateKey; the test is not proving anything")
	}
	got, ok := res.BindingCertificate.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatal("BindingCertificate.PrivateKey is not a crypto.Signer, so crypto/tls cannot use it")
	}
	if !key.PublicKey.Equal(got.Public()) {
		t.Error("the returned signer does not wrap the binding certificate's key")
	}
	if res.BindingCertificate.Leaf == nil || !res.BindingCertificate.Leaf.Equal(leaf) {
		t.Error("BindingCertificate.Leaf is not the signer's certificate")
	}
}

func rootsFor(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}
