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
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testKey is a non-nil placeholder private key for fixtures that never perform a real TLS handshake.
var testKey = struct{}{}

var (
	fixtureKeyOnce sync.Once
	fixtureKey     *rsa.PrivateKey
	fixtureKeyErr  error
)

func parseableTestCert(t *testing.T, serial int64) tls.Certificate {
	t.Helper()
	fixtureKeyOnce.Do(func() {
		fixtureKey, fixtureKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if fixtureKeyErr != nil {
		t.Fatal(fixtureKeyErr)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "fixture"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &fixtureKey.PublicKey, fixtureKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: testKey, Leaf: leaf}
}

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

// signerTestCertCN is the subject of the certificate signerOnlyTestCert issues, so a test server can
// confirm it saw that certificate rather than merely some certificate.
const signerTestCertCN = "msal-go-signer-test"

// signerOnlyTestCert returns a self-signed certificate whose key is only ever a crypto.Signer.
func signerOnlyTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: signerTestCertCN},
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
// are covered -- which is why each subtest asserts the version it actually negotiated. Without that
// assertion, losing MaxVersion would silently collapse both subtests onto one padding scheme.
func TestBuildMtlsClientSignerHandshake(t *testing.T) {
	cert := signerOnlyTestCert(t)
	for _, test := range []struct {
		name       string
		maxVersion uint16
	}{
		{"TLS 1.2", tls.VersionTLS12},
		{"TLS 1.3", tls.VersionTLS13},
	} {
		t.Run(test.name, func(t *testing.T) {
			// The handler runs on the server's goroutine while the assertions run on this one, so
			// what it observes has to be read under a lock; tlsRecorder is the same guard
			// mtls_network_test.go uses. A server per subtest keeps the recorder unshared.
			recorder := &tlsRecorder{}
			server := httptest.NewUnstartedServer(recorder.handler(http.StatusOK, ""))
			server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
			server.StartTLS()
			defer server.Close()

			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())

			client, err := BuildMtlsClient(cert, nil)
			if err != nil {
				t.Fatalf("BuildMtlsClient error: %v", err)
			}
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
			if resp.TLS == nil {
				t.Fatal("the response carries no TLS connection state")
			}
			if resp.TLS.Version != test.maxVersion {
				t.Errorf("negotiated TLS version %#04x, want %#04x; this subtest only covers the padding "+
					"scheme its name claims when the version matches", resp.TLS.Version, test.maxVersion)
			}
			hits := recorder.snapshot()
			if len(hits) != 1 {
				t.Fatalf("server handled %d requests, want 1", len(hits))
			}
			if hits[0].numCerts != 1 {
				t.Errorf("server saw %d client certificates, want 1", hits[0].numCerts)
			}
			if hits[0].clientCN != signerTestCertCN {
				t.Errorf("server saw client certificate %q, want %q", hits[0].clientCN, signerTestCertCN)
			}
		})
	}
}

func TestBuildMtlsClient(t *testing.T) {
	cert := parseableTestCert(t, 1)
	client, err := BuildMtlsClient(cert, nil)
	if err != nil {
		t.Fatalf("BuildMtlsClient error: %v", err)
	}
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
	client, err := BuildMtlsClient(cert, nil)
	if err != nil {
		t.Fatalf("BuildMtlsClient error: %v", err)
	}
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
	certAValue := parseableTestCert(t, 2)
	certBValue := parseableTestCert(t, 3)
	certA := &certAValue
	certB := &certBValue

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
	certValue := parseableTestCert(t, 4)
	cert := &certValue
	c := &Client{}
	c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient { return nil })
	if _, err := c.mtlsClient(cert); err == nil {
		t.Error("mtlsClient with nil-returning factory = nil error, want error")
	}
}

func TestMtlsClientUsesFactoryOverride(t *testing.T) {
	certValue := parseableTestCert(t, 5)
	cert := &certValue
	sentinel := &http.Client{}
	c := &Client{}
	c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient { return sentinel })

	got, err := c.mtlsClient(cert)
	if err != nil {
		t.Fatalf("mtlsClient error: %v", err)
	}

	t.Run("factory client copy and redirect policy", func(t *testing.T) {
		certValue := parseableTestCert(t, 24)
		cert := &certValue
		transport := &notATransport{}
		caller := &http.Client{Transport: transport, Timeout: 17 * time.Second}
		c := &Client{}
		c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient { return caller })

		gotClient, err := c.mtlsClient(cert)
		if err != nil {
			t.Fatal(err)
		}
		got := gotClient.(*http.Client)
		if got == caller {
			t.Fatal("factory result wasn't copied")
		}
		if caller.CheckRedirect != nil {
			t.Error("MSAL mutated the caller-owned client's redirect policy")
		}
		if got.Transport != caller.Transport || got.Timeout != caller.Timeout {
			t.Error("the client copy didn't preserve caller configuration")
		}
		if got.CheckRedirect == nil {
			t.Fatal("the client copy has no redirect refusal")
		}
		req, err := http.NewRequest(http.MethodPost, "https://redirect.example/token", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := got.CheckRedirect(req, nil); err == nil {
			t.Fatal("default custom-factory client followed a redirect")
		}

		explicitErr := errors.New("explicit redirect policy")
		explicit := &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return explicitErr },
		}
		c = &Client{}
		c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient { return explicit })
		gotClient, err = c.mtlsClient(cert)
		if err != nil {
			t.Fatal(err)
		}
		if err := gotClient.(*http.Client).CheckRedirect(req, nil); !errors.Is(err, explicitErr) {
			t.Fatalf("explicit redirect policy returned %v, want %v", err, explicitErr)
		}
		if explicit.CheckRedirect == nil {
			t.Error("the caller's explicit policy was mutated")
		}
	})

	t.Run("factory rejects opaque client", func(t *testing.T) {
		certValue := parseableTestCert(t, 25)
		c := &Client{}
		c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient { return &recordingClient{} })
		if _, err := c.mtlsClient(&certValue); err == nil {
			t.Fatal("factory returning a non-*http.Client succeeded without an enforceable redirect policy")
		} else if !strings.Contains(err.Error(), "*http.Client") {
			t.Fatalf("error = %v, want concrete client requirement", err)
		}
	})
	if got == sentinel {
		t.Error("mtlsClient returned the caller-owned client instead of a shallow copy")
	}
	if got.(*http.Client).Transport != sentinel.Transport {
		t.Error("mtlsClient's copy did not preserve the caller's transport")
	}
}
