// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package comm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// testKey is a non-nil placeholder private key for fixtures that never perform a real TLS handshake.
var testKey = struct{}{}

// signerKey models a non-exportable key such as a Windows KeyGuard (VBS-isolated) key: it satisfies
// crypto.Signer by delegating to an RSA key it never exposes, so nothing can type assert it to an
// *rsa.PrivateKey. A zero signerKey is a placeholder for fixtures that never sign anything.
type signerKey struct {
	key *rsa.PrivateKey
}

func (s signerKey) Public() crypto.PublicKey {
	if s.key == nil {
		return nil
	}
	return &s.key.PublicKey
}

func (s signerKey) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.key == nil {
		return nil, nil
	}
	return s.key.Sign(r, digest, opts)
}

// signerOnlyTestCert returns a self-signed certificate whose key is only ever a crypto.Signer.
func signerOnlyTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "msal-go-signer-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: signerKey{key: key}}
}

// TestBuildMtlsClientSignerHandshake proves crypto/tls can complete a client-certificate handshake
// when the certificate's key is only a crypto.Signer, which is all a non-exportable key
// (KeyGuard/CNG/HSM) can ever be. TLS 1.3 signs with RSA-PSS and TLS 1.2 with PKCS#1 v1.5, so both
// are covered.
func TestBuildMtlsClientSignerHandshake(t *testing.T) {
	cert := signerOnlyTestCert(t)
	var gotClientCerts int
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClientCerts = len(r.TLS.PeerCertificates)
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())

	for _, test := range []struct {
		name       string
		maxVersion uint16
	}{
		{"TLS 1.2", tls.VersionTLS12},
		{"TLS 1.3", tls.VersionTLS13},
	} {
		t.Run(test.name, func(t *testing.T) {
			gotClientCerts = 0
			client := BuildMtlsClient(cert, nil)
			transport, ok := client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("client.Transport = %T, want *http.Transport", client.Transport)
			}
			transport.TLSClientConfig.RootCAs = roots
			transport.TLSClientConfig.MaxVersion = test.maxVersion

			resp, err := client.Get(server.URL)
			if err != nil {
				t.Fatalf("handshake with a signer-only key failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
			}
			if gotClientCerts != 1 {
				t.Errorf("server saw %d client certificates, want 1", gotClientCerts)
			}
		})
	}
}

func TestBuildMtlsClient(t *testing.T) {
	cert := tls.Certificate{Certificate: [][]byte{{0x01, 0x02, 0x03}}}
	client := BuildMtlsClient(cert, nil)
	if client == nil {
		t.Fatal("BuildMtlsClient returned nil")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client.Transport = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if got := len(transport.TLSClientConfig.Certificates); got != 1 {
		t.Fatalf("TLSClientConfig.Certificates has %d entries, want 1", got)
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.2)", transport.TLSClientConfig.MinVersion, tls.VersionTLS12)
	}
}

func TestBuildMtlsClientCarriesSignerKey(t *testing.T) {
	// A non-exportable key (KeyGuard/CNG/HSM) can only be a crypto.Signer, so the transport must pass
	// tls.Certificate.PrivateKey through untouched rather than assert a concrete key type.
	cert := signerOnlyTestCert(t)
	client := BuildMtlsClient(cert, nil)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client.Transport = %T, want *http.Transport", client.Transport)
	}
	if got := len(transport.TLSClientConfig.Certificates); got != 1 {
		t.Fatalf("TLSClientConfig.Certificates has %d entries, want 1", got)
	}
	if transport.TLSClientConfig.Certificates[0].PrivateKey != cert.PrivateKey {
		t.Error("the signer didn't reach TLSClientConfig.Certificates intact")
	}
}

func TestMtlsClientCachePerThumbprint(t *testing.T) {
	certA := &tls.Certificate{Certificate: [][]byte{{0xAA, 0xBB}}, PrivateKey: testKey}
	certB := &tls.Certificate{Certificate: [][]byte{{0xCC, 0xDD}}, PrivateKey: testKey}

	var built int
	c := &Client{}
	c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient {
		built++
		return &http.Client{}
	})

	first, err := c.mtlsClient(certA)
	if err != nil {
		t.Fatalf("mtlsClient(certA) error: %v", err)
	}
	second, err := c.mtlsClient(certA)
	if err != nil {
		t.Fatalf("mtlsClient(certA) second call error: %v", err)
	}
	if first != second {
		t.Error("expected the same cached client for the same certificate thumbprint")
	}
	if built != 1 {
		t.Errorf("factory called %d times for the same cert, want 1", built)
	}

	if _, err := c.mtlsClient(certB); err != nil {
		t.Fatalf("mtlsClient(certB) error: %v", err)
	}
	if built != 2 {
		t.Errorf("factory called %d times total, want 2 (one per distinct cert)", built)
	}
}

func TestMtlsClientRequiresCert(t *testing.T) {
	c := &Client{}
	if _, err := c.mtlsClient(nil); err == nil {
		t.Error("mtlsClient(nil) = nil error, want error")
	}
	if _, err := c.mtlsClient(&tls.Certificate{}); err == nil {
		t.Error("mtlsClient(empty) = nil error, want error")
	}
	if _, err := c.mtlsClient(&tls.Certificate{Certificate: [][]byte{{}}, PrivateKey: testKey}); err == nil {
		t.Error("mtlsClient(empty leaf) = nil error, want error")
	}
	if _, err := c.mtlsClient(&tls.Certificate{Certificate: [][]byte{{0x01}}}); err == nil {
		t.Error("mtlsClient(no private key) = nil error, want error")
	}
}

func TestMtlsClientRejectsNilFactoryResult(t *testing.T) {
	cert := &tls.Certificate{Certificate: [][]byte{{0x22}}, PrivateKey: testKey}
	c := &Client{}
	c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient { return nil })
	if _, err := c.mtlsClient(cert); err == nil {
		t.Error("mtlsClient with nil-returning factory = nil error, want error")
	}
}

func TestMtlsClientUsesFactoryOverride(t *testing.T) {
	cert := &tls.Certificate{Certificate: [][]byte{{0x11}}, PrivateKey: testKey}
	sentinel := &http.Client{}
	c := &Client{}
	c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient { return sentinel })

	got, err := c.mtlsClient(cert)
	if err != nil {
		t.Fatalf("mtlsClient error: %v", err)
	}
	if got != sentinel {
		t.Error("mtlsClient did not return the client produced by the override factory")
	}
}
