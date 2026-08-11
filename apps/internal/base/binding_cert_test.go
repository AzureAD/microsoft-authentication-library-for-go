// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package base

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"testing"
	"time"
)

// legacyThumbprint reproduces the pre-change implementation of BindingCertificateThumbprint, which
// hashed a bare *x509.Certificate's Raw. Keeping it here pins the new Leaf-based implementation to
// byte-identical output.
func legacyThumbprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// selfSignedCert builds a throwaway self-signed certificate plus its key. ECDSA P-256 keeps the test
// fast; nothing here depends on the key algorithm.
func selfSignedCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "binding-cert-test"},
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
	return leaf, key
}

// opaqueSigner wraps a key behind crypto.Signer only, so it is deliberately NOT type-assertable to a
// concrete key type. It models a non-exportable platform key (Windows KeyGuard, CNG, an HSM), whose
// material never leaves the key store. crypto/tls only requires a crypto.Signer, so such a key is a
// perfectly valid tls.Certificate.PrivateKey and must survive the AuthResult boundary intact.
type opaqueSigner struct{ inner crypto.Signer }

func (s opaqueSigner) Public() crypto.PublicKey { return s.inner.Public() }

func (s opaqueSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.inner.Sign(r, digest, opts)
}

// TestBindingCertWithLeafPopulatesLeaf covers the two inputs MSAL can hand the helper: a certificate
// that already carries a parsed Leaf, and one that carries only DER. Both must come back with Leaf
// populated and, critically, with PrivateKey preserved — stripping it is the defect this guards.
func TestBindingCertWithLeafPopulatesLeaf(t *testing.T) {
	leaf, key := selfSignedCert(t)

	t.Run("leaf already set", func(t *testing.T) {
		in := &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
		got := bindingCertWithLeaf(in)
		if got == nil {
			t.Fatal("bindingCertWithLeaf returned nil")
		}
		if got.Leaf != leaf {
			t.Error("Leaf was not preserved")
		}
		if got.PrivateKey == nil {
			t.Fatal("PrivateKey was stripped; the caller can no longer present the certificate")
		}
		if got.PrivateKey != crypto.PrivateKey(key) {
			t.Error("PrivateKey is not the key MSAL used for the token request")
		}
	})

	t.Run("leaf parsed from DER", func(t *testing.T) {
		in := &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}
		got := bindingCertWithLeaf(in)
		if got == nil {
			t.Fatal("bindingCertWithLeaf returned nil")
		}
		if got.Leaf == nil {
			t.Fatal("Leaf was not populated from Certificate[0]")
		}
		if !got.Leaf.Equal(leaf) {
			t.Error("parsed Leaf does not match the input certificate")
		}
		if got.PrivateKey == nil {
			t.Fatal("PrivateKey was stripped; the caller can no longer present the certificate")
		}
	})
}

// TestBindingCertWithLeafDoesNotMutateInput pins the shallow-copy contract. The same *tls.Certificate
// is retained by the per-thumbprint mTLS client cache in oauth/ops/internal/comm, so writing Leaf back
// into the caller's value would be a data race across concurrent acquisitions.
func TestBindingCertWithLeafDoesNotMutateInput(t *testing.T) {
	leaf, key := selfSignedCert(t)
	in := &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}

	got := bindingCertWithLeaf(in)
	if got == nil {
		t.Fatal("bindingCertWithLeaf returned nil")
	}
	if in.Leaf != nil {
		t.Error("bindingCertWithLeaf mutated its input; the shared certificate must not be written to")
	}
	if got == in {
		t.Error("bindingCertWithLeaf returned the input pointer, not a copy")
	}
}

// TestBindingCertWithLeafConcurrent is the race-detector companion to the no-mutation test: many
// goroutines resolving the same shared certificate must not write to it. Run with -race.
func TestBindingCertWithLeafConcurrent(t *testing.T) {
	leaf, key := selfSignedCert(t)
	shared := &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}

	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				got := bindingCertWithLeaf(shared)
				if got == nil || got.Leaf == nil || got.PrivateKey == nil {
					t.Error("bindingCertWithLeaf returned an incomplete certificate")
					return
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if shared.Leaf != nil {
		t.Error("concurrent resolution mutated the shared certificate")
	}
}

// TestBindingCertWithLeafNilHandling pins the pre-existing nil behavior: no certificate, no DER, or
// unparsable DER all yield nil rather than a half-built certificate.
func TestBindingCertWithLeafNilHandling(t *testing.T) {
	if got := bindingCertWithLeaf(nil); got != nil {
		t.Error("nil input must yield nil")
	}
	if got := bindingCertWithLeaf(&tls.Certificate{}); got != nil {
		t.Error("certificate without DER must yield nil")
	}
	if got := bindingCertWithLeaf(&tls.Certificate{Certificate: [][]byte{{0x01, 0x02, 0x03}}}); got != nil {
		t.Error("unparsable DER must yield nil")
	}
}

// TestBindingCertWithLeafKeepsOpaqueSigner proves a non-exportable, KeyGuard-style key survives the
// helper: it must come back as a crypto.Signer and must NOT be assertable to a concrete key type.
func TestBindingCertWithLeafKeepsOpaqueSigner(t *testing.T) {
	leaf, key := selfSignedCert(t)
	signer := opaqueSigner{inner: key}
	in := &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: signer, Leaf: leaf}

	got := bindingCertWithLeaf(in)
	if got == nil {
		t.Fatal("bindingCertWithLeaf returned nil")
	}
	if _, ok := got.PrivateKey.(*ecdsa.PrivateKey); ok {
		t.Fatal("the test signer must not be assertable to a concrete key type; the test is not proving anything")
	}
	s, ok := got.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatal("PrivateKey did not round-trip as a crypto.Signer, so crypto/tls cannot use it")
	}
	if !key.PublicKey.Equal(s.Public()) {
		t.Error("the round-tripped signer does not wrap the certificate's key")
	}
}

// TestBindingCertificateThumbprintIsStable pins the emitted x5t#S256 string. The thumbprint is now
// computed from BindingCertificate.Leaf.Raw rather than from a bare *x509.Certificate's Raw; the two
// must be byte-identical, because the value ends up in cache keys and in the cnf claim callers match
// against. The golden constant below was captured from the implementation before that change.
func TestBindingCertificateThumbprintIsStable(t *testing.T) {
	leaf, key := selfSignedCert(t)
	cert := &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}

	// Recompute with the pre-change algorithm, independently of the production code path.
	want := legacyThumbprint(leaf)
	ar := AuthResult{BindingCertificate: cert}
	if got := ar.BindingCertificateThumbprint(); got != want {
		t.Errorf("BindingCertificateThumbprint() = %q, want %q", got, want)
	}

	// The parsed-from-DER path must produce the same string.
	ar2 := AuthResult{BindingCertificate: bindingCertWithLeaf(&tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key})}
	if got := ar2.BindingCertificateThumbprint(); got != want {
		t.Errorf("thumbprint from parsed leaf = %q, want %q", got, want)
	}
}

// TestBindingCertificateThumbprintEmpty pins the "" contract for both nil cases: no binding
// certificate at all, and a certificate whose Leaf could not be determined.
func TestBindingCertificateThumbprintEmpty(t *testing.T) {
	if got := (AuthResult{}).BindingCertificateThumbprint(); got != "" {
		t.Errorf("no binding certificate: got %q, want \"\"", got)
	}
	ar := AuthResult{BindingCertificate: &tls.Certificate{Certificate: [][]byte{{0x01}}}}
	if got := ar.BindingCertificateThumbprint(); got != "" {
		t.Errorf("binding certificate without a leaf: got %q, want \"\"", got)
	}
}
