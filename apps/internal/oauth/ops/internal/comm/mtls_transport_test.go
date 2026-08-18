// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package comm

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

// recordingClient is an HTTPClient that records CloseIdleConnections calls, so eviction and
// race-loser paths can be asserted without a real transport.
type recordingClient struct {
	mu     sync.Mutex
	closed int
}

func (r *recordingClient) Do(*http.Request) (*http.Response, error) { return nil, nil }

func (r *recordingClient) CloseIdleConnections() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed++
}

func (r *recordingClient) closeCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

// TestBuildMtlsClientUsesConfiguredTransport is the regression test for the strongest finding in the
// review: BuildMtlsClient cloned http.DefaultTransport unconditionally, so an application's
// WithHTTPClient settings (corporate proxy, custom RootCAs, custom dialer, tracing) were silently
// dropped on every mTLS token request.
func TestBuildMtlsClientUsesConfiguredTransport(t *testing.T) {
	proxyURL, err := url.Parse("http://proxy.example:8080")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	configured := &http.Transport{
		Proxy:                 func(*http.Request) (*url.URL, error) { return proxyURL, nil },
		MaxIdleConns:          7,
		ResponseHeaderTimeout: 11 * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs:            roots,
			ServerName:         "sni.example",
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		},
	}
	base := &http.Client{Transport: configured}

	cert := tls.Certificate{Certificate: [][]byte{{0x01, 0x02, 0x03}}}
	client := BuildMtlsClient(cert, base)
	if client == nil {
		t.Fatal("BuildMtlsClient returned nil")
	}
	got, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client.Transport = %T, want *http.Transport", client.Transport)
	}
	if got == configured {
		t.Fatal("BuildMtlsClient returned the caller's transport instead of a clone")
	}
	if got.Proxy == nil {
		t.Error("the caller's Proxy was dropped")
	} else if u, err := got.Proxy(nil); err != nil || u == nil || u.String() != proxyURL.String() {
		t.Errorf("Proxy resolved to (%v, %v), want %s", u, err, proxyURL)
	}
	if got.MaxIdleConns != configured.MaxIdleConns {
		t.Errorf("MaxIdleConns = %d, want %d", got.MaxIdleConns, configured.MaxIdleConns)
	}
	if got.ResponseHeaderTimeout != configured.ResponseHeaderTimeout {
		t.Errorf("ResponseHeaderTimeout = %s, want %s", got.ResponseHeaderTimeout, configured.ResponseHeaderTimeout)
	}
	if got.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if got.TLSClientConfig.RootCAs != roots {
		t.Error("the caller's RootCAs were dropped")
	}
	if got.TLSClientConfig.ServerName != "sni.example" {
		t.Errorf("ServerName = %q, want sni.example", got.TLSClientConfig.ServerName)
	}
	if len(got.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("TLSClientConfig.Certificates has %d entries, want 1", len(got.TLSClientConfig.Certificates))
	}

	// The caller's transport and tls.Config must be untouched.
	if got.TLSClientConfig == configured.TLSClientConfig {
		t.Fatal("the caller's *tls.Config is shared with the mTLS client")
	}
	if len(configured.TLSClientConfig.Certificates) != 0 {
		t.Error("BuildMtlsClient wrote the binding certificate into the caller's tls.Config")
	}
}

// TestBuildMtlsClientFallsBackToDefaultTransport covers the base clients BuildMtlsClient can't
// introspect: nil, a non-*http.Client implementation, and an *http.Client with a custom
// RoundTripper. All must still yield a usable transport carrying the binding certificate.
func TestBuildMtlsClientFallsBackToDefaultTransport(t *testing.T) {
	cert := tls.Certificate{Certificate: [][]byte{{0x01, 0x02, 0x03}}}
	for _, test := range []struct {
		desc string
		base HTTPClient
	}{
		{desc: "nil base", base: nil},
		{desc: "non-http.Client base", base: &recordingClient{}},
		{desc: "custom RoundTripper", base: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, nil })}},
		{desc: "nil transport", base: &http.Client{}},
	} {
		t.Run(test.desc, func(t *testing.T) {
			client := BuildMtlsClient(cert, test.base)
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
		})
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestBuildMtlsClientKeepsStrongerMinVersion pins that the TLS 1.2 floor only ever raises the
// caller's minimum. A caller who pinned TLS 1.3 must not be silently downgraded.
func TestBuildMtlsClientKeepsStrongerMinVersion(t *testing.T) {
	base := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	}}
	client := BuildMtlsClient(tls.Certificate{Certificate: [][]byte{{0x01}}}, base)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client.Transport = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.3)", transport.TLSClientConfig.MinVersion, tls.VersionTLS13)
	}
}

// TestBuildMtlsClientClearsGetClientCertificate proves the binding certificate wins. A
// caller-supplied GetClientCertificate takes precedence over Certificates during the handshake, so
// leaving it in place would silently suppress the binding certificate and the token request would
// present the wrong (or no) client certificate.
func TestBuildMtlsClientClearsGetClientCertificate(t *testing.T) {
	other := &tls.Certificate{Certificate: [][]byte{{0xFF}}}
	base := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return other, nil },
		},
	}}
	client := BuildMtlsClient(tls.Certificate{Certificate: [][]byte{{0x01}}}, base)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client.Transport = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig.GetClientCertificate != nil {
		t.Error("GetClientCertificate survived and would override the binding certificate")
	}
}

// TestMtlsClientFactoryNotCalledUnderLock is the deadlock regression test. The factory used to be
// invoked while mtlsMu was held, so a re-entrant factory - one that calls back into the same Client -
// deadlocked permanently. Building outside the lock makes this safe. The test would hang (and be
// killed by the test timeout) if the fix regressed.
func TestMtlsClientFactoryNotCalledUnderLock(t *testing.T) {
	certA := &tls.Certificate{Certificate: [][]byte{{0xAA}}, PrivateKey: testKey}
	certB := &tls.Certificate{Certificate: [][]byte{{0xBB}}, PrivateKey: testKey}

	c := &Client{}
	c.SetMtlsClientFactory(func(cert tls.Certificate) HTTPClient {
		if len(cert.Certificate) > 0 && len(cert.Certificate[0]) > 0 && cert.Certificate[0][0] == 0xAA {
			// Re-enter the Client from inside the factory.
			if _, err := c.mtlsClient(certB); err != nil {
				t.Errorf("re-entrant mtlsClient failed: %v", err)
			}
		}
		return &http.Client{}
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := c.mtlsClient(certA); err != nil {
			t.Errorf("mtlsClient(certA) failed: %v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("mtlsClient deadlocked: the factory is being invoked while mtlsMu is held")
	}
}

// TestMtlsClientConcurrentSameCertPublishesOneClient covers the double-check publish. Many
// goroutines racing on the same thumbprint must all end up with the same client, and every client
// that loses the race must have its idle connections closed rather than being silently dropped.
func TestMtlsClientConcurrentSameCertPublishesOneClient(t *testing.T) {
	cert := &tls.Certificate{Certificate: [][]byte{{0x42}}, PrivateKey: testKey}

	var mu sync.Mutex
	built := []*recordingClient{}
	c := &Client{}
	c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient {
		rc := &recordingClient{}
		mu.Lock()
		built = append(built, rc)
		mu.Unlock()
		// Widen the window between building and publishing so losers are likely.
		time.Sleep(time.Millisecond)
		return rc
	})

	const goroutines = 16
	results := make(chan HTTPClient, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := c.mtlsClient(cert)
			if err != nil {
				t.Errorf("mtlsClient failed: %v", err)
				results <- nil
				return
			}
			results <- got
		}()
	}
	wg.Wait()
	close(results)

	var winner HTTPClient
	for got := range results {
		if got == nil {
			t.Fatal("mtlsClient returned nil")
		}
		if winner == nil {
			winner = got
		} else if got != winner {
			t.Fatal("concurrent callers got different clients for the same thumbprint")
		}
	}

	mu.Lock()
	defer mu.Unlock()
	for _, rc := range built {
		if HTTPClient(rc) == winner {
			if n := rc.closeCount(); n != 0 {
				t.Errorf("the published client was closed %d times", n)
			}
			continue
		}
		if n := rc.closeCount(); n != 1 {
			t.Errorf("a client that lost the publish race was closed %d times, want 1", n)
		}
	}
}

// TestMtlsClientCacheCapClears pins the cap-then-clear policy, which is exact parity with MSAL .NET's
// SimpleHttpClientFactory.CheckAndManageCache (clear at 1000, no eviction ordering, no disposal).
// Unlike .NET, every dropped client is asked to close its idle connections, because Go's
// http.Transport pools keep-alive sockets that nothing else reclaims.
func TestMtlsClientCacheCapClears(t *testing.T) {
	var mu sync.Mutex
	built := []*recordingClient{}
	c := &Client{}
	c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient {
		rc := &recordingClient{}
		mu.Lock()
		built = append(built, rc)
		mu.Unlock()
		return rc
	})

	certFor := func(i int) *tls.Certificate {
		return &tls.Certificate{
			Certificate: [][]byte{{byte(i), byte(i >> 8), byte(i >> 16)}},
			PrivateKey:  testKey,
		}
	}
	for i := 0; i < maxMtlsClients; i++ {
		if _, err := c.mtlsClient(certFor(i)); err != nil {
			t.Fatalf("mtlsClient(%d) failed: %v", i, err)
		}
	}
	c.mtlsMu.Lock()
	size := len(c.mtlsClients)
	c.mtlsMu.Unlock()
	if size != maxMtlsClients {
		t.Fatalf("cache holds %d entries, want %d", size, maxMtlsClients)
	}

	// One more entry trips the cap: the cache is cleared and only the newcomer remains.
	if _, err := c.mtlsClient(certFor(maxMtlsClients)); err != nil {
		t.Fatalf("mtlsClient past the cap failed: %v", err)
	}
	c.mtlsMu.Lock()
	size = len(c.mtlsClients)
	c.mtlsMu.Unlock()
	if size != 1 {
		t.Fatalf("cache holds %d entries after the cap was tripped, want 1", size)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(built) != maxMtlsClients+1 {
		t.Fatalf("factory produced %d clients, want %d", len(built), maxMtlsClients+1)
	}
	for i, rc := range built[:maxMtlsClients] {
		if n := rc.closeCount(); n != 1 {
			t.Fatalf("evicted client %d had CloseIdleConnections called %d times, want 1", i, n)
		}
	}
	if n := built[maxMtlsClients].closeCount(); n != 0 {
		t.Errorf("the surviving client was closed %d times, want 0", n)
	}
}

// TestSetMtlsClientFactoryClosesDiscardedClients covers the reset path: replacing the factory drops
// the whole cache, and those clients' pooled sockets must be released.
func TestSetMtlsClientFactoryClosesDiscardedClients(t *testing.T) {
	cert := &tls.Certificate{Certificate: [][]byte{{0x55}}, PrivateKey: testKey}
	rc := &recordingClient{}
	c := &Client{}
	c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient { return rc })
	if _, err := c.mtlsClient(cert); err != nil {
		t.Fatalf("mtlsClient failed: %v", err)
	}

	c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient { return &http.Client{} })
	if n := rc.closeCount(); n != 1 {
		t.Errorf("discarded client had CloseIdleConnections called %d times, want 1", n)
	}
	c.mtlsMu.Lock()
	size := len(c.mtlsClients)
	c.mtlsMu.Unlock()
	if size != 0 {
		t.Errorf("cache holds %d entries after the factory was replaced, want 0", size)
	}
}

// TestMtlsClientRejectsTypedNilFactoryResult covers the typed-nil hole. A factory written as
// "var c *http.Client; return c" hands back an interface that is not == nil but panics on Do, so a
// plain nil check would cache it.
func TestMtlsClientRejectsTypedNilFactoryResult(t *testing.T) {
	cert := &tls.Certificate{Certificate: [][]byte{{0x33}}, PrivateKey: testKey}
	c := &Client{}
	c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient {
		var typedNil *http.Client
		return typedNil
	})
	if _, err := c.mtlsClient(cert); err == nil {
		t.Error("mtlsClient with a typed-nil-returning factory = nil error, want error")
	}
	c.mtlsMu.Lock()
	size := len(c.mtlsClients)
	c.mtlsMu.Unlock()
	if size != 0 {
		t.Errorf("an unusable client was cached: %d entries", size)
	}
}
