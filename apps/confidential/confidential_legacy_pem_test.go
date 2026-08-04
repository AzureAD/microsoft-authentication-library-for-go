// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"strings"
	"testing"
	"time"
)

const legacyPEMWarningSubstr = "Legacy PEM encryption detected"

// testKeyAndCert generates a self-signed certificate and its RSA private key for use in tests.
func testKeyAndCert(t *testing.T) (*rsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "msal-go-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return key, tmpl, certPEM
}

// legacyEncryptedKeyPEM builds an RFC 1423 (DEK-Info) encrypted PEM block whose decrypted payload
// is itself a PEM-encoded "RSA PRIVATE KEY" block, matching how CertFromPEM re-decodes the
// decrypted bytes.
func legacyEncryptedKeyPEM(t *testing.T, key *rsa.PrivateKey, password string) []byte {
	t.Helper()
	inner := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	//nolint:staticcheck // x509.EncryptPEMBlock is deprecated; used only to construct legacy test fixtures.
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", inner, []byte(password), x509.PEMCipher3DES)
	if err != nil {
		t.Fatalf("encrypting legacy PEM block: %v", err)
	}
	return pem.EncodeToMemory(block)
}

// pkcs8KeyPEM builds a modern, unencrypted PKCS#8 "PRIVATE KEY" PEM block.
func pkcs8KeyPEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling PKCS#8 key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// pkcs1KeyPEM builds an unencrypted PKCS#1 "RSA PRIVATE KEY" PEM block (no DEK-Info header).
func pkcs1KeyPEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
}

// captureLog redirects the standard logger's output for the duration of fn and returns what was written.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	origOut := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(origOut)
		log.SetFlags(origFlags)
	}()
	fn()
	return buf.String()
}

// Test 1 — Legacy encrypted PEM still decrypts successfully after the warning change.
func TestCertFromPEM_LegacyEncrypted_DecryptsAndWarns(t *testing.T) {
	key, _, certPEM := testKeyAndCert(t)
	const password = "correct horse battery"
	pemData := append(append([]byte{}, certPEM...), legacyEncryptedKeyPEM(t, key, password)...)

	var certs []*x509.Certificate
	var priv interface{}
	var err error
	out := captureLog(t, func() {
		certs, priv, err = CertFromPEM(pemData, password)
	})
	if err != nil {
		t.Fatalf("CertFromPEM returned error: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("expected at least one certificate, got none")
	}
	if priv == nil {
		t.Fatal("expected a non-nil private key")
	}
	if !strings.Contains(out, legacyPEMWarningSubstr) {
		t.Fatalf("expected log to contain %q, got %q", legacyPEMWarningSubstr, out)
	}
	// The returned key must match the key we encrypted.
	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", priv)
	}
	if rsaKey.N.Cmp(key.N) != 0 {
		t.Fatal("recovered key does not match original key")
	}
}

// Test 2 — Incorrect password for legacy encrypted PEM returns an error.
func TestCertFromPEM_LegacyEncrypted_WrongPassword(t *testing.T) {
	key, _, certPEM := testKeyAndCert(t)
	pemData := append(append([]byte{}, certPEM...), legacyEncryptedKeyPEM(t, key, "the-right-password")...)

	certs, priv, err := CertFromPEM(pemData, "the-WRONG-password")
	if err == nil {
		t.Fatal("expected an error for incorrect password, got nil")
	}
	if !strings.Contains(err.Error(), "could not decrypt encrypted PEM block") {
		t.Fatalf("expected error to mention 'could not decrypt encrypted PEM block', got %q", err.Error())
	}
	if certs != nil || priv != nil {
		t.Fatal("expected no cert or key to be returned on failure")
	}
}

// Test 3 — Modern PKCS#8 PEM is unaffected: it loads and does not trigger the legacy warning.
func TestCertFromPEM_PKCS8_NoWarning(t *testing.T) {
	key, _, certPEM := testKeyAndCert(t)
	pemData := append(append([]byte{}, certPEM...), pkcs8KeyPEM(t, key)...)

	var certs []*x509.Certificate
	var priv interface{}
	var err error
	out := captureLog(t, func() {
		certs, priv, err = CertFromPEM(pemData, "")
	})
	if err != nil {
		t.Fatalf("CertFromPEM returned error: %v", err)
	}
	if len(certs) == 0 || priv == nil {
		t.Fatal("expected a certificate and key from PKCS#8 PEM")
	}
	if strings.Contains(out, legacyPEMWarningSubstr) {
		t.Fatalf("legacy warning must not fire for PKCS#8 keys, got log %q", out)
	}
}

// Test 4 — Unencrypted PEM is unaffected: it loads and does not trigger the legacy warning.
func TestCertFromPEM_Unencrypted_NoWarning(t *testing.T) {
	key, _, certPEM := testKeyAndCert(t)
	pemData := append(append([]byte{}, certPEM...), pkcs1KeyPEM(t, key)...)

	var certs []*x509.Certificate
	var priv interface{}
	var err error
	out := captureLog(t, func() {
		certs, priv, err = CertFromPEM(pemData, "")
	})
	if err != nil {
		t.Fatalf("CertFromPEM returned error: %v", err)
	}
	if len(certs) == 0 || priv == nil {
		t.Fatal("expected a certificate and key from unencrypted PEM")
	}
	if strings.Contains(out, legacyPEMWarningSubstr) {
		t.Fatalf("legacy warning must not fire for unencrypted PEM, got log %q", out)
	}
}

// Test 5 — Abuse path: a tampered/unsupported DEK-Info header does not silently bypass error handling.
func TestCertFromPEM_TamperedDEKInfo_Errors(t *testing.T) {
	key, _, certPEM := testKeyAndCert(t)
	legacy := legacyEncryptedKeyPEM(t, key, "pw")
	// Corrupt the DEK-Info header to reference an unknown cipher so decryption cannot proceed.
	tampered := bytes.Replace(legacy, []byte("DEK-Info: DES-EDE3-CBC"), []byte("DEK-Info: BOGUS-CIPHER"), 1)
	if bytes.Equal(tampered, legacy) {
		t.Fatal("test setup failed: DEK-Info header was not replaced")
	}
	pemData := append(append([]byte{}, certPEM...), tampered...)

	certs, priv, err := CertFromPEM(pemData, "pw")
	if err == nil {
		t.Fatal("expected an error for tampered DEK-Info header, got nil")
	}
	if certs != nil || priv != nil {
		t.Fatal("expected no cert or key to be returned for tampered PEM")
	}
}
