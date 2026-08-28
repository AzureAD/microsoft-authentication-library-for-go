// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
)

// signerOnlyKey stands in for a non-exportable key such as a Windows KeyGuard (VBS-isolated) key: it
// satisfies crypto.Signer by delegating to an RSA key it never exposes, so no code can type assert it
// to an *rsa.PrivateKey. Tests using it therefore run anywhere, without CNG.
type signerOnlyKey struct {
	key *rsa.PrivateKey
}

func (s signerOnlyKey) Public() crypto.PublicKey {
	return &s.key.PublicKey
}

func (s signerOnlyKey) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(r, digest, opts)
}

// loadTestCertFile reads a PEM fixture holding a certificate chain and its RSA private key.
func loadTestCertFile(t *testing.T, path string) ([]*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	pemData, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	certs, key, err := CertFromPEM(pemData, "")
	if err != nil {
		t.Fatal(err)
	}
	k, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("expected an RSA private key in testdata")
	}
	return certs, k
}

// testSignerCert returns a certificate chain paired with a signer-only key, in the shape a caller
// with a KeyGuard/CNG key would build: DER chain leaf first plus a crypto.Signer. The chain fixture
// holds a leaf and an intermediate, so chain-order assertions are meaningful.
func testSignerCert(t *testing.T) (tls.Certificate, []*x509.Certificate, signerOnlyKey) {
	t.Helper()
	certs, k := loadTestCertFile(t, "../testdata/test-cert-chain.pem")
	if len(certs) < 2 {
		t.Fatalf("expected a chain of at least 2 certs, got %d", len(certs))
	}
	if !k.PublicKey.Equal(certs[0].PublicKey) {
		t.Fatal("expected the chain fixture to be leaf first")
	}
	der := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		der = append(der, cert.Raw)
	}
	signer := signerOnlyKey{key: k}
	return tls.Certificate{Certificate: der, PrivateKey: signer}, certs, signer
}

// TestNewCredFromTLSCertificate verifies a signer-only key produces a credential that carries the
// signer, the leaf, and a leaf-first x5c, whether or not tls.Certificate.Leaf was populated.
func TestNewCredFromTLSCertificate(t *testing.T) {
	tlsCert, certs, signer := testSignerCert(t)
	for _, withLeaf := range []bool{false, true} {
		t.Run(fmt.Sprintf("leaf=%v", withLeaf), func(t *testing.T) {
			c := tlsCert
			if withLeaf {
				c.Leaf = certs[0]
			}
			cred, err := NewCredFromTLSCertificate(c)
			if err != nil {
				t.Fatal(err)
			}
			if !cred.signerOnly {
				t.Error("a credential whose key isn't an *rsa.PrivateKey must be marked signer-only")
			}
			if cred.cert == nil || !cred.cert.Equal(certs[0]) {
				t.Error("credential's certificate isn't the leaf")
			}
			if cred.key != crypto.PrivateKey(signer) {
				t.Error("credential didn't retain the caller's signer")
			}
			if len(cred.x5c) != len(certs) {
				t.Fatalf("x5c has %d entries, want %d", len(cred.x5c), len(certs))
			}
			// the whole chain must be preserved in the caller's order, which is leaf first
			for i, cert := range certs {
				if want := base64.StdEncoding.EncodeToString(cert.Raw); cred.x5c[i] != want {
					t.Errorf("x5c[%d] isn't the caller's certificate at that position", i)
				}
			}
		})
	}
}

// TestNewCredFromTLSCertificateRejectsNonLeafFirstChain verifies a chain that isn't leaf first is
// rejected rather than silently producing a credential whose x5c and binding certificate disagree
// with the leaf actually presented on the handshake.
func TestNewCredFromTLSCertificateRejectsNonLeafFirstChain(t *testing.T) {
	certs, k := loadTestCertFile(t, "../testdata/test-cert-chain-reverse.pem")
	if k.PublicKey.Equal(certs[0].PublicKey) {
		t.Fatal("expected the reverse fixture to lead with a cert that isn't the signer's leaf")
	}
	der := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		der = append(der, cert.Raw)
	}
	_, err := NewCredFromTLSCertificate(tls.Certificate{
		Certificate: der,
		PrivateKey:  signerOnlyKey{key: k},
	})
	if err == nil {
		t.Fatal("expected an error because the chain doesn't lead with the signer's certificate")
	}
}

// TestNewCredFromTLSCertificateBindingCert verifies the signer reaches the binding certificate MSAL
// hands to the mTLS transport, i.e. nothing between the constructor and tls.Config re-asserts
// *rsa.PrivateKey.
func TestNewCredFromTLSCertificateBindingCert(t *testing.T) {
	tlsCert, certs, signer := testSignerCert(t)
	cred, err := NewCredFromTLSCertificate(tlsCert)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(fakeAuthority, fakeClientID, cred)
	if err != nil {
		t.Fatal(err)
	}
	bindingCert, err := client.resolveMtlsBindingCert()
	if err != nil {
		t.Fatal(err)
	}
	if bindingCert.PrivateKey != crypto.PrivateKey(signer) {
		t.Errorf("binding certificate's PrivateKey = %T, want the caller's signer", bindingCert.PrivateKey)
	}
	if bindingCert.Leaf == nil || !bindingCert.Leaf.Equal(certs[0]) {
		t.Error("binding certificate's leaf isn't the credential's certificate")
	}
	if len(bindingCert.Certificate) != len(certs) {
		t.Fatalf("binding certificate chain has %d entries, want %d", len(bindingCert.Certificate), len(certs))
	}
	// the chain MSAL presents on the handshake must match the caller's, leaf first
	for i, cert := range certs {
		if !bytes.Equal(bindingCert.Certificate[i], cert.Raw) {
			t.Errorf("binding certificate chain entry %d isn't the caller's certificate at that position", i)
		}
	}
}

func TestNewCredFromTLSCertificateError(t *testing.T) {
	tlsCert, certs, _ := testSignerCert(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		cert tls.Certificate
	}{
		{"no certificate", tls.Certificate{PrivateKey: tlsCert.PrivateKey}},
		{"empty leaf", tls.Certificate{Certificate: [][]byte{{}}, PrivateKey: tlsCert.PrivateKey}},
		{"no key", tls.Certificate{Certificate: tlsCert.Certificate}},
		{"key isn't a signer", tls.Certificate{Certificate: tlsCert.Certificate, PrivateKey: struct{}{}}},
		{"key doesn't match the leaf", tls.Certificate{
			Certificate: tlsCert.Certificate,
			PrivateKey:  signerOnlyKey{key: otherKey},
		}},
		{"unparseable leaf", tls.Certificate{
			Certificate: [][]byte{{0x01, 0x02, 0x03}},
			PrivateKey:  tlsCert.PrivateKey,
		}},
		{"Leaf disagrees with the chain", tls.Certificate{
			// Leaf claims a cert whose key matches, but the DER actually presented on the handshake
			// doesn't parse, so the mismatch must be caught rather than trusted.
			Certificate: [][]byte{{0x01, 0x02, 0x03}},
			PrivateKey:  tlsCert.PrivateKey,
			Leaf:        certs[0],
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewCredFromTLSCertificate(test.cert); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// nilSigner models the typed nil a caller produces by handing over an uninitialized pointer, e.g.
//
//	var s *nilSigner
//	tls.Certificate{PrivateKey: s}
//
// The interface value is non-nil, so a crypto.Signer type assertion succeeds, and Public dereferences
// the receiver. Anything calling Public without a nil check therefore panics instead of erroring.
type nilSigner struct {
	key *rsa.PrivateKey
}

func (s *nilSigner) Public() crypto.PublicKey {
	return &s.key.PublicKey
}

func (s *nilSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(r, digest, opts)
}

// TestNewCredFromTypedNilSigner is a regression test: a typed-nil crypto.Signer satisfies the type
// assertion in both constructors because the interface value is non-nil, so calling Public on it
// panics with a nil pointer dereference. Both constructors must return an error instead.
func TestNewCredFromTypedNilSigner(t *testing.T) {
	_, certs, _ := testSignerCert(t)
	der := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		der = append(der, cert.Raw)
	}
	var typedNil *nilSigner
	// the premise of the test: a typed nil pointer still satisfies the crypto.Signer assertion both
	// constructors make, so it reaches the code that calls Public
	if _, ok := crypto.PrivateKey(typedNil).(crypto.Signer); !ok {
		t.Fatal("expected a typed nil pointer to satisfy crypto.Signer")
	}
	for _, test := range []struct {
		name    string
		newCred func() (Credential, error)
	}{
		{"NewCredFromCert", func() (Credential, error) {
			return NewCredFromCert(certs, typedNil)
		}},
		{"NewCredFromTLSCertificate", func() (Credential, error) {
			return NewCredFromTLSCertificate(tls.Certificate{Certificate: der, PrivateKey: typedNil})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("a typed-nil signer panicked instead of returning an error: %v", r)
				}
			}()
			if _, err := test.newCred(); err == nil {
				t.Fatal("expected an error because the signer is a nil pointer")
			}
		})
	}
}

// TestNewCredFromCertWithSigner covers the same non-exportable key arriving through NewCredFromCert.
func TestNewCredFromCertWithSigner(t *testing.T) {
	_, certs, signer := testSignerCert(t)
	cred, err := NewCredFromCert(certs, signer)
	if err != nil {
		t.Fatal(err)
	}
	if !cred.signerOnly {
		t.Error("a credential whose key isn't an *rsa.PrivateKey must be marked signer-only")
	}
	if cred.cert == nil || !cred.cert.Equal(certs[0]) {
		t.Error("credential's certificate isn't the signing cert")
	}
	if len(cred.x5c) != len(certs) {
		t.Fatalf("x5c has %d entries, want %d", len(cred.x5c), len(certs))
	}
	if cred.x5c[0] != base64.StdEncoding.EncodeToString(certs[0].Raw) {
		t.Error("the signing cert must be first in x5c")
	}
}

// TestNewCredFromCertSignerError verifies relaxing NewCredFromCert didn't widen what it accepts
// beyond RSA, and that a mismatched signer is still rejected.
func TestNewCredFromCertSignerError(t *testing.T) {
	_, certs, _ := testSignerCert(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		key  crypto.PrivateKey
	}{
		{"ECDSA signer", ecKey},
		{"signer for another key", signerOnlyKey{key: otherKey}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewCredFromCert(certs, test.key); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// TestSignerOnlyCredentialRejectsAssertion verifies a non-exportable key fails the client assertion
// path with actionable guidance instead of an opaque error from the JWT library.
func TestSignerOnlyCredentialRejectsAssertion(t *testing.T) {
	tlsCert, _, _ := testSignerCert(t)
	cred, err := NewCredFromTLSCertificate(tlsCert)
	if err != nil {
		t.Fatal(err)
	}
	client, err := fakeClient(accesstokens.TokenResponse{}, cred, fakeAuthority)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AcquireTokenByCredential(context.Background(), tokenScope)
	if err == nil {
		t.Fatal("expected an error because a signer-only key can't sign a client assertion")
	}
	if !strings.Contains(err.Error(), "WithMtlsProofOfPossession") {
		t.Errorf("error %q should point the caller to WithMtlsProofOfPossession()", err)
	}
}

// TestSignerOnlyCredentialMtlsPoP is the end-to-end case for a KeyGuard-style key: the signer is
// handed to the mTLS transport, the request carries no client_assertion, and the token is bound to
// the certificate.
func TestSignerOnlyCredentialMtlsPoP(t *testing.T) {
	tlsCert, certs, signer := testSignerCert(t)
	cred, err := NewCredFromTLSCertificate(tlsCert)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tenant"
	lmo := "login.microsoftonline.com"
	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenant)))

	var gotCert tls.Certificate
	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(mockClient),
		WithMtlsHTTPClient(func(c tls.Certificate) *http.Client {
			gotCert = c
			return &http.Client{Transport: mockRoundTripper{client: mockClient}}
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	var gotBody url.Values
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mtlsPoPTokenBody("mtls-access-token", 3600)),
		mock.WithCallback(func(r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			gotBody, _ = url.ParseQuery(string(b))
		}),
	)

	res, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}

	if gotCert.PrivateKey != crypto.PrivateKey(signer) {
		t.Errorf("the mTLS transport got PrivateKey %T, want the caller's signer", gotCert.PrivateKey)
	}
	if len(gotCert.Certificate) != len(certs) {
		t.Fatalf("the mTLS transport got %d chain entries, want %d", len(gotCert.Certificate), len(certs))
	}
	for i, cert := range certs {
		if !bytes.Equal(gotCert.Certificate[i], cert.Raw) {
			t.Errorf("the mTLS transport's chain entry %d isn't the caller's certificate at that position", i)
		}
	}
	if gotBody.Get("client_assertion") != "" {
		t.Error("mTLS PoP request must not send client_assertion")
	}
	if got := gotBody.Get("token_type"); got != "mtls_pop" {
		t.Errorf("token_type = %q, want mtls_pop", got)
	}
	if res.BindingCertificate == nil || res.BindingCertificate.Leaf == nil || !res.BindingCertificate.Leaf.Equal(certs[0]) {
		t.Error("BindingCertificate isn't the credential's leaf certificate")
	}
	if res.BindingCertificate.PrivateKey == nil {
		t.Error("BindingCertificate.PrivateKey is nil; the non-exportable signer must survive to the caller")
	}
}
