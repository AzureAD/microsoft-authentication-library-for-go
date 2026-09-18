// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package comm

import (
	"context"
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
	"net/url"
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

// setTestMtlsClientFactory adapts certificate-aware fixtures from the original override to the
// augmenter contract. Focused tests exercise contract failures and middleware behavior directly.
func (c *Client) setTestMtlsClientFactory(factory func(tls.Certificate) HTTPClient) {
	c.SetMtlsClientFactory(func(augment func(*http.Client) (*http.Client, error)) (HTTPClient, error) {
		augmented, err := augment(&http.Client{})
		if err != nil {
			return nil, err
		}
		transport := augmented.Transport.(*http.Transport)
		return factory(transport.TLSClientConfig.Certificates[0]), nil
	})
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
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Errorf("closing response body: %v", err)
				}
			}()
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
	c.setTestMtlsClientFactory(func(tls.Certificate) HTTPClient {
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
	third, err := c.mtlsClient(certA)
	if err != nil {
		t.Fatalf("mtlsClient(certA) after certB error: %v", err)
	}
	if third != first {
		t.Error("A -> B -> A did not reuse certificate A's cached client")
	}
	if built != 2 {
		t.Errorf("factory called %d times after A -> B -> A, want 2", built)
	}

	t.Run("different certificates build concurrently", func(t *testing.T) {
		c := &Client{}
		started := make(chan struct{}, 2)
		release := make(chan struct{})
		c.setTestMtlsClientFactory(func(tls.Certificate) HTTPClient {
			started <- struct{}{}
			<-release
			return &recordingClient{}
		})

		type result struct {
			client HTTPClient
			err    error
		}
		results := make(chan result, 2)
		for _, cert := range []*tls.Certificate{certA, certB} {
			cert := cert
			go func() {
				client, err := c.mtlsClient(cert)
				results <- result{client: client, err: err}
			}()
		}
		for i := 0; i < 2; i++ {
			select {
			case <-started:
			case <-time.After(10 * time.Second):
				t.Fatal("distinct-certificate factories did not run concurrently")
			}
		}
		close(release)

		first := <-results
		second := <-results
		if first.err != nil || second.err != nil {
			t.Fatalf("concurrent builds returned errors: %v, %v", first.err, second.err)
		}
		if first.client == second.client {
			t.Fatal("different certificates shared one specialized client")
		}
	})

	t.Run("different certificates isolate pools and session caches", func(t *testing.T) {
		shared := tls.NewLRUClientSessionCache(0)
		base := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			ClientSessionCache: shared,
		}}}
		c := &Client{}
		c.SetMtlsClientFactory(func(augment func(*http.Client) (*http.Client, error)) (HTTPClient, error) {
			return augment(base)
		})

		clientA, err := c.mtlsClient(certA)
		if err != nil {
			t.Fatal(err)
		}
		clientB, err := c.mtlsClient(certB)
		if err != nil {
			t.Fatal(err)
		}
		if clientA == clientB {
			t.Fatal("different certificates shared an HTTP client")
		}
		httpA := clientA.(*http.Client)
		httpB := clientB.(*http.Client)
		transportA := httpA.Transport.(*http.Transport)
		transportB := httpB.Transport.(*http.Transport)
		if transportA == transportB {
			t.Fatal("different certificates shared a connection pool")
		}
		cacheA := transportA.TLSClientConfig.ClientSessionCache
		cacheB := transportB.TLSClientConfig.ClientSessionCache
		if cacheA == nil || cacheB == nil {
			t.Fatal("configured session caching was unexpectedly disabled")
		}
		if cacheA == shared || cacheB == shared || cacheA == cacheB {
			t.Fatal("different certificates shared TLS session state")
		}

		reusedA, err := c.mtlsClient(certA)
		if err != nil {
			t.Fatal(err)
		}
		if reusedA != clientA {
			t.Fatal("certificate A didn't reuse its isolated client after certificate B")
		}
	})
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
	c.setTestMtlsClientFactory(func(tls.Certificate) HTTPClient { return nil })
	if _, err := c.mtlsClient(cert); err == nil {
		t.Error("mtlsClient with nil-returning factory = nil error, want error")
	}
}

func TestMtlsClientFactoryContractFailsClosed(t *testing.T) {
	certValue := parseableTestCert(t, 26)
	factoryErr := errors.New("factory failed")

	type state struct {
		augmentErr error
	}
	tests := []struct {
		name           string
		factory        func(*recordingClient, *state) MtlsClientFactory
		want           []string
		wantFactoryErr bool
		wantAugmentErr bool
		returnsClient  bool
	}{
		{
			name: "no augment call",
			factory: func(client *recordingClient, _ *state) MtlsClientFactory {
				return func(func(*http.Client) (*http.Client, error)) (HTTPClient, error) {
					return client, nil
				}
			},
			want:          []string{"exactly once", "got 0 calls"},
			returnsClient: true,
		},
		{
			name: "multiple augment calls",
			factory: func(client *recordingClient, _ *state) MtlsClientFactory {
				return func(augment func(*http.Client) (*http.Client, error)) (HTTPClient, error) {
					_, _ = augment(&http.Client{})
					_, _ = augment(&http.Client{})
					return client, nil
				}
			},
			want:          []string{"called augment 2 times", "exactly once"},
			returnsClient: true,
		},
		{
			name: "nil base",
			factory: func(client *recordingClient, _ *state) MtlsClientFactory {
				return func(augment func(*http.Client) (*http.Client, error)) (HTTPClient, error) {
					_, _ = augment(nil)
					return client, nil
				}
			},
			want:          []string{"nil base *http.Client"},
			returnsClient: true,
		},
		{
			name: "nil result",
			factory: func(_ *recordingClient, _ *state) MtlsClientFactory {
				return func(augment func(*http.Client) (*http.Client, error)) (HTTPClient, error) {
					if _, err := augment(&http.Client{}); err != nil {
						return nil, err
					}
					return nil, nil
				}
			},
			want: []string{"returned a nil client"},
		},
		{
			name: "factory error",
			factory: func(client *recordingClient, _ *state) MtlsClientFactory {
				return func(augment func(*http.Client) (*http.Client, error)) (HTTPClient, error) {
					if _, err := augment(&http.Client{}); err != nil {
						return nil, err
					}
					return client, factoryErr
				}
			},
			want:           []string{"factory failed"},
			wantFactoryErr: true,
			returnsClient:  true,
		},
		{
			name: "swallowed augmentation error",
			factory: func(client *recordingClient, s *state) MtlsClientFactory {
				return func(augment func(*http.Client) (*http.Client, error)) (HTTPClient, error) {
					_, s.augmentErr = augment(&http.Client{Transport: notATransport{}})
					return client, nil
				}
			},
			want:           []string{"not an *http.Transport"},
			wantAugmentErr: true,
			returnsClient:  true,
		},
		{
			name: "factory and augmentation errors",
			factory: func(client *recordingClient, s *state) MtlsClientFactory {
				return func(augment func(*http.Client) (*http.Client, error)) (HTTPClient, error) {
					_, s.augmentErr = augment(nil)
					return client, factoryErr
				}
			},
			want:           []string{"nil base *http.Client", "factory failed"},
			wantFactoryErr: true,
			wantAugmentErr: true,
			returnsClient:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			returned := &recordingClient{}
			state := &state{}
			c := &Client{}
			c.SetMtlsClientFactory(test.factory(returned, state))

			var response struct{}
			err := c.URLFormCallWithCertificate(
				context.Background(),
				"https://example.invalid/token",
				url.Values{"grant_type": {"client_credentials"}},
				&response,
				&certValue,
			)
			if err == nil {
				t.Fatal("factory contract violation reached request transmission")
			}
			for _, want := range test.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %v, want text %q", err, want)
				}
			}
			if test.wantFactoryErr && !errors.Is(err, factoryErr) {
				t.Errorf("error %v doesn't preserve factory error %v", err, factoryErr)
			}
			if test.wantAugmentErr && !errors.Is(err, state.augmentErr) {
				t.Errorf("error %v doesn't preserve augmentation error %v", err, state.augmentErr)
			}
			if got := returned.doCount(); got != 0 {
				t.Errorf("specialized client transmitted %d requests, want 0", got)
			}
			wantClosed := 0
			if test.returnsClient {
				wantClosed = 1
			}
			if got := returned.closeCount(); got != wantClosed {
				t.Errorf("specialized client CloseIdleConnections calls = %d, want %d", got, wantClosed)
			}
		})
	}
}

func TestMtlsClientUsesFactoryCapability(t *testing.T) {
	certValue := parseableTestCert(t, 5)
	cert := &certValue
	sentinel := &recordingClient{}
	c := &Client{}
	c.SetMtlsClientFactory(func(augment func(*http.Client) (*http.Client, error)) (HTTPClient, error) {
		if _, err := augment(&http.Client{}); err != nil {
			return nil, err
		}
		return sentinel, nil
	})

	got, err := c.mtlsClient(cert)
	if err != nil {
		t.Fatalf("mtlsClient error: %v", err)
	}
	if got != sentinel {
		t.Fatal("mtlsClient did not cache the specialized wrapper returned by the factory")
	}

	t.Run("augmenter owns client copy and redirect policy", func(t *testing.T) {
		certValue := parseableTestCert(t, 24)
		cert := &certValue
		transport := &http.Transport{}
		caller := &http.Client{Transport: transport, Timeout: 17 * time.Second}
		c := &Client{}
		c.SetMtlsClientFactory(func(augment func(*http.Client) (*http.Client, error)) (HTTPClient, error) {
			return augment(caller)
		})

		gotClient, err := c.mtlsClient(cert)
		if err != nil {
			t.Fatal(err)
		}
		got := gotClient.(*http.Client)
		if got == caller {
			t.Fatal("augment returned the caller's base client without copying it")
		}
		if caller.CheckRedirect != nil {
			t.Error("MSAL mutated the caller-owned client's redirect policy")
		}
		if got.Transport == caller.Transport || got.Timeout != caller.Timeout {
			t.Error("the augmented client didn't clone the transport and preserve caller configuration")
		}
		if got.CheckRedirect == nil {
			t.Fatal("the augmented client has no redirect refusal")
		}
		req, err := http.NewRequest(http.MethodPost, "https://redirect.example/token", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := got.CheckRedirect(req, nil); err == nil {
			t.Fatal("augmented client followed a redirect by default")
		}

		explicitErr := errors.New("explicit redirect policy")
		explicit := &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return explicitErr },
		}
		c = &Client{}
		c.SetMtlsClientFactory(func(augment func(*http.Client) (*http.Client, error)) (HTTPClient, error) {
			return augment(explicit)
		})
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

	t.Run("factory can return opaque middleware client", func(t *testing.T) {
		certValue := parseableTestCert(t, 25)
		sentinel := &recordingClient{}
		c := &Client{}
		c.SetMtlsClientFactory(func(augment func(*http.Client) (*http.Client, error)) (HTTPClient, error) {
			if _, err := augment(&http.Client{}); err != nil {
				return nil, err
			}
			return sentinel, nil
		})
		got, err := c.mtlsClient(&certValue)
		if err != nil {
			t.Fatal(err)
		}
		if got != sentinel {
			t.Fatal("factory's middleware client wasn't preserved")
		}
	})
}
