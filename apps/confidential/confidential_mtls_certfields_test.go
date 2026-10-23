// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
)

// pssRefusingSigner models a key that cannot do RSA-PSS at all: CNG, KeyGuard, several HSMs and most
// smart cards are in this category. It is the reason a caller sets
// tls.Certificate.SupportedSignatureAlgorithms, and the reason MSAL must not drop it.
type pssRefusingSigner struct {
	key *rsa.PrivateKey
}

func (s pssRefusingSigner) Public() crypto.PublicKey { return &s.key.PublicKey }

func (s pssRefusingSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, ok := opts.(*rsa.PSSOptions); ok {
		return nil, errors.New("this key cannot produce RSA-PSS signatures")
	}
	return s.key.Sign(r, digest, opts)
}

// nilReceiverSigner is used as a typed-nil pointer, which is non-nil as an interface value. Its
// methods dereference the receiver, so validBindingCertificate must reject it before calling one.
type nilReceiverSigner struct {
	key *rsa.PrivateKey
}

func (s *nilReceiverSigner) Public() crypto.PublicKey { return &s.key.PublicKey }

func (s *nilReceiverSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(r, digest, opts)
}

// TestNewCredFromTLSCertificatePreservesHandshakeFields proves the handshake-only fields of the
// caller's tls.Certificate survive into the certificate MSAL presents for an mTLS PoP request.
//
// SupportedSignatureAlgorithms is the one that matters. crypto/tls uses it to decide which signature
// schemes the key can produce; a signer with no RSA-PSS support advertises only the PKCS #1 v1.5
// schemes, which is what keeps the connection on TLS 1.2. Dropping it lets the handshake select PSS
// and the signer then fails, which is exactly the non-exportable-key case this constructor exists to
// serve. Before this was fixed, resolveMtlsBindingCert rebuilt a bare tls.Certificate from Cert, Key
// and X5c, so all three fields were silently lost.
func TestNewCredFromTLSCertificatePreservesHandshakeFields(t *testing.T) {
	tlsCert, _, _ := testSignerCert(t)
	algs := []tls.SignatureScheme{tls.PKCS1WithSHA256, tls.PKCS1WithSHA384}
	staple := []byte{0x30, 0x03, 0x0a, 0x01, 0x00}
	scts := [][]byte{{0x01, 0x02}, {0x03, 0x04}}
	tlsCert.SupportedSignatureAlgorithms = algs
	tlsCert.OCSPStaple = staple
	tlsCert.SignedCertificateTimestamps = scts

	cred, err := NewCredFromTLSCertificate(tlsCert)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New("https://login.microsoftonline.com/tenant", "client-id", cred)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.resolveMtlsBindingCert(nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(got.SupportedSignatureAlgorithms) != len(algs) {
		t.Fatalf("SupportedSignatureAlgorithms: got %v, want %v; crypto/tls would then assume the key can produce every scheme the certificate allows and select RSA-PSS", got.SupportedSignatureAlgorithms, algs)
	}
	for i, alg := range algs {
		if got.SupportedSignatureAlgorithms[i] != alg {
			t.Errorf("SupportedSignatureAlgorithms[%d] = %v, want %v", i, got.SupportedSignatureAlgorithms[i], alg)
		}
	}
	if !bytes.Equal(got.OCSPStaple, staple) {
		t.Errorf("OCSPStaple = %x, want %x", got.OCSPStaple, staple)
	}
	if len(got.SignedCertificateTimestamps) != len(scts) {
		t.Fatalf("SignedCertificateTimestamps: got %d entries, want %d", len(got.SignedCertificateTimestamps), len(scts))
	}
	for i, sct := range scts {
		if !bytes.Equal(got.SignedCertificateTimestamps[i], sct) {
			t.Errorf("SignedCertificateTimestamps[%d] = %x, want %x", i, got.SignedCertificateTimestamps[i], sct)
		}
	}
}

// TestNewCredFromTLSCertificateCopiesHandshakeFields proves those fields are copied rather than
// aliased, so a caller reusing its buffers cannot rewrite what MSAL will present.
func TestNewCredFromTLSCertificateCopiesHandshakeFields(t *testing.T) {
	tlsCert, _, _ := testSignerCert(t)
	tlsCert.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.PKCS1WithSHA256}
	tlsCert.OCSPStaple = []byte{0x01, 0x02, 0x03}
	tlsCert.SignedCertificateTimestamps = [][]byte{{0x0a, 0x0b}}

	cred, err := NewCredFromTLSCertificate(tlsCert)
	if err != nil {
		t.Fatal(err)
	}

	tlsCert.SupportedSignatureAlgorithms[0] = tls.PSSWithSHA256
	tlsCert.OCSPStaple[0] = 0xff
	tlsCert.SignedCertificateTimestamps[0][0] = 0xff

	if cred.tlsFields.SupportedSignatureAlgorithms[0] != tls.PKCS1WithSHA256 {
		t.Error("mutating the caller's SupportedSignatureAlgorithms changed the credential")
	}
	if cred.tlsFields.OCSPStaple[0] != 0x01 {
		t.Error("mutating the caller's OCSPStaple changed the credential")
	}
	if cred.tlsFields.SignedCertificateTimestamps[0][0] != 0x0a {
		t.Error("mutating the caller's SignedCertificateTimestamps changed the credential")
	}
}

// TestNewCredFromTLSCertificateUnsetHandshakeFieldsStayNil keeps the common case honest: a caller who
// sets none of these must not end up with non-nil empty slices, which crypto/tls does not treat the
// same way. An empty SupportedSignatureAlgorithms is not "no constraint".
func TestNewCredFromTLSCertificateUnsetHandshakeFieldsStayNil(t *testing.T) {
	tlsCert, _, _ := testSignerCert(t)
	cred, err := NewCredFromTLSCertificate(tlsCert)
	if err != nil {
		t.Fatal(err)
	}
	if cred.tlsFields.SupportedSignatureAlgorithms != nil {
		t.Error("unset SupportedSignatureAlgorithms became non-nil")
	}
	if cred.tlsFields.OCSPStaple != nil {
		t.Error("unset OCSPStaple became non-nil")
	}
	if cred.tlsFields.SignedCertificateTimestamps != nil {
		t.Error("unset SignedCertificateTimestamps became non-nil")
	}
}

// TestPSSRefusingSignerReachesTheHandshake proves the constraint is carried all the way to the
// certificate crypto/tls would use, with a key that genuinely cannot do RSA-PSS. The end-to-end
// handshake that consumes it lives in the comm package, next to the transport that runs it.
func TestPSSRefusingSignerReachesTheHandshake(t *testing.T) {
	certs, k := loadTestCertFile(t, "../testdata/test-cert-chain.pem")
	signer := pssRefusingSigner{key: k}
	if _, err := signer.Sign(nil, make([]byte, 32), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}); err == nil {
		t.Fatal("fixture is wrong: this signer must refuse RSA-PSS")
	}

	der := make([][]byte, 0, len(certs))
	for _, c := range certs {
		der = append(der, c.Raw)
	}
	cred, err := NewCredFromTLSCertificate(tls.Certificate{
		Certificate:                  der,
		PrivateKey:                   signer,
		SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.PKCS1WithSHA256},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := New("https://login.microsoftonline.com/tenant", "client-id", cred)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.resolveMtlsBindingCert(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SupportedSignatureAlgorithms) != 1 || got.SupportedSignatureAlgorithms[0] != tls.PKCS1WithSHA256 {
		t.Fatalf("a key that cannot do RSA-PSS reached the handshake advertising %v, so crypto/tls may select PSS and the handshake fails", got.SupportedSignatureAlgorithms)
	}
}

// TestNewCredFromCertIsolatesCertificateDER proves the credential does not alias the caller's
// certificate. NewCredFromCert used to retain the caller's *x509.Certificate by pointer while
// encoding x5c as a snapshot, so a caller mutating its own cert.Raw afterwards changed the
// credential's x5t/x5t#S256 thumbprint and left it disagreeing with x5c and with the bytes presented
// on the wire. NewCredFromTLSCertificate already parsed a private copy for this reason.
func TestNewCredFromCertIsolatesCertificateDER(t *testing.T) {
	certs, k := loadTestCertFile(t, "../testdata/test-cert-chain.pem")
	// Hand the constructor certificates whose Raw we still own and can scribble on.
	owned := make([]*x509.Certificate, len(certs))
	for i, c := range certs {
		der := append([]byte(nil), c.Raw...)
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		owned[i] = parsed
	}
	cred, err := NewCredFromCert(owned, k)
	if err != nil {
		t.Fatal(err)
	}
	if cred.cert == owned[0] {
		t.Fatal("credential retained the caller's *x509.Certificate, so the caller can still mutate what MSAL presents")
	}
	before := append([]byte(nil), cred.cert.Raw...)
	wantX5c := cred.x5c[0]

	// A caller reusing its DER buffer. This is the mutation the fix has to survive.
	for i := range owned[0].Raw {
		owned[0].Raw[i] ^= 0xff
	}

	if !bytes.Equal(cred.cert.Raw, before) {
		t.Error("mutating the caller's certificate changed the credential's leaf, so the thumbprint MSAL binds the token to is caller-controlled after construction")
	}
	if cred.x5c[0] != wantX5c {
		t.Error("mutating the caller's certificate changed x5c")
	}
	// The whole point: the leaf and the x5c entry must still describe the same bytes.
	if cred.x5c[0] != base64.StdEncoding.EncodeToString(cred.cert.Raw) {
		t.Error("credential's leaf and x5c[0] describe different certificates")
	}
}

// TestValidBindingCertificateRejectsTypedNilSigner proves a typed-nil crypto.Signer is rejected
// rather than dereferenced. A nil *T stored in an interface is not a nil interface, so the
// type assertion above it succeeds and the first method call panics.
// NewCredFromTLSCertificate already guarded both shapes; this path did not.
func TestValidBindingCertificateRejectsTypedNilSigner(t *testing.T) {
	tlsCert, _, _ := testSignerCert(t)
	cert := tlsCert
	cert.PrivateKey = (*nilReceiverSigner)(nil)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("validBindingCertificate panicked on a typed-nil signer instead of returning an error: %v", r)
		}
	}()
	_, err := validBindingCertificate(&cert)
	if err == nil {
		t.Fatal("expected an error for a typed-nil crypto.Signer")
	}
	if !strings.Contains(err.Error(), "nil crypto.Signer") {
		t.Errorf("error should name the problem, got: %v", err)
	}
}

// TestValidBindingCertificateRejectsTypedNilPublicKey proves a signer returning a typed-nil public
// key is rejected before it reaches Equal, which asserts its argument's type and then dereferences
// it.
func TestValidBindingCertificateRejectsTypedNilPublicKey(t *testing.T) {
	tlsCert, _, _ := testSignerCert(t)
	cert := tlsCert
	cert.PrivateKey = nilPublicKeySigner{}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("validBindingCertificate panicked on a typed-nil public key instead of returning an error: %v", r)
		}
	}()
	_, err := validBindingCertificate(&cert)
	if err == nil {
		t.Fatal("expected an error for a signer whose public key is a typed-nil pointer")
	}
	if !strings.Contains(err.Error(), "public key must not be nil") {
		t.Errorf("error should name the problem, got: %v", err)
	}
}

// TestValidBindingCertificateStillAcceptsGoodCertificate guards the guards: the two rejections above
// must not turn away a legitimate signer-backed certificate.
func TestValidBindingCertificateStillAcceptsGoodCertificate(t *testing.T) {
	tlsCert, certs, _ := testSignerCert(t)
	got, err := validBindingCertificate(&tlsCert)
	if err != nil {
		t.Fatal(err)
	}
	if got.Leaf == nil || !got.Leaf.Equal(certs[0]) {
		t.Error("expected the leaf to be populated from Certificate[0]")
	}
}
