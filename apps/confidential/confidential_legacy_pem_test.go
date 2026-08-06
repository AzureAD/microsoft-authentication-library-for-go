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
	"math/big"
	"strings"
	"testing"
	"time"
)

// encryptedPEMErrSubstr is a stable fragment of the error CertFromPEM returns for encrypted PEM.
const encryptedPEMErrSubstr = "not supported"

// testKeyAndCert generates a self-signed certificate and its RSA private key for use in tests.
// It returns the key, the parsed certificate, and the PEM-encoded certificate.
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
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return key, cert, certPEM
}

// legacyEncryptedKeyPEM builds an RFC 1423 (DEK-Info) encrypted "RSA PRIVATE KEY" PEM block for
// use as a rejected-input fixture.
func legacyEncryptedKeyPEM(t *testing.T, key *rsa.PrivateKey, password string) []byte {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(key)
	//nolint:staticcheck // x509.EncryptPEMBlock is deprecated; used only to construct legacy test fixtures.
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", der, []byte(password), x509.PEMCipher3DES)
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

// Legacy RFC 1423 encrypted PEM is rejected with guidance, regardless of the supplied password.
func TestCertFromPEM_LegacyEncrypted_Rejected(t *testing.T) {
	key, _, certPEM := testKeyAndCert(t)
	const filePassword = "correct horse battery"
	legacy := legacyEncryptedKeyPEM(t, key, filePassword)
	pemData := append(append([]byte{}, certPEM...), legacy...)

	for _, password := range []string{filePassword, "wrong-password", ""} {
		t.Run("password="+password, func(t *testing.T) {
			certs, priv, err := CertFromPEM(pemData, password)
			if err == nil {
				t.Fatal("expected an error for legacy encrypted PEM, got nil")
			}
			if !strings.Contains(err.Error(), encryptedPEMErrSubstr) {
				t.Fatalf("expected error to contain %q, got %q", encryptedPEMErrSubstr, err.Error())
			}
			if certs != nil || priv != nil {
				t.Fatal("expected no cert or key to be returned for encrypted PEM")
			}
		})
	}
}

// A tampered/unsupported DEK-Info header is still detected and rejected — it cannot bypass the check.
func TestCertFromPEM_TamperedDEKInfo_Rejected(t *testing.T) {
	key, _, certPEM := testKeyAndCert(t)
	legacy := legacyEncryptedKeyPEM(t, key, "pw")
	tampered := bytes.Replace(legacy, []byte("DEK-Info: DES-EDE3-CBC"), []byte("DEK-Info: BOGUS-CIPHER"), 1)
	if bytes.Equal(tampered, legacy) {
		t.Fatal("test setup failed: DEK-Info header was not replaced")
	}
	pemData := append(append([]byte{}, certPEM...), tampered...)

	certs, priv, err := CertFromPEM(pemData, "pw")
	if err == nil {
		t.Fatal("expected an error for tampered DEK-Info header, got nil")
	}
	if !strings.Contains(err.Error(), encryptedPEMErrSubstr) {
		t.Fatalf("expected error to contain %q, got %q", encryptedPEMErrSubstr, err.Error())
	}
	if certs != nil || priv != nil {
		t.Fatal("expected no cert or key to be returned for tampered PEM")
	}
}

// A modern, unencrypted PKCS#8 private key loads successfully.
func TestCertFromPEM_PKCS8_Loads(t *testing.T) {
	key, cert, certPEM := testKeyAndCert(t)
	pemData := append(append([]byte{}, certPEM...), pkcs8KeyPEM(t, key)...)

	certs, priv, err := CertFromPEM(pemData, "")
	if err != nil {
		t.Fatalf("CertFromPEM returned error: %v", err)
	}
	if len(certs) != 1 || priv == nil {
		t.Fatalf("expected one certificate and a key, got %d certs, key nil=%v", len(certs), priv == nil)
	}
	if certs[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatal("returned certificate does not match the generated certificate")
	}
}

// An unencrypted PKCS#1 private key loads successfully.
func TestCertFromPEM_Unencrypted_Loads(t *testing.T) {
	key, cert, certPEM := testKeyAndCert(t)
	pemData := append(append([]byte{}, certPEM...), pkcs1KeyPEM(t, key)...)

	certs, priv, err := CertFromPEM(pemData, "")
	if err != nil {
		t.Fatalf("CertFromPEM returned error: %v", err)
	}
	if len(certs) != 1 || priv == nil {
		t.Fatalf("expected one certificate and a key, got %d certs, key nil=%v", len(certs), priv == nil)
	}
	if certs[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatal("returned certificate does not match the generated certificate")
	}
}
