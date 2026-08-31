// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package comm

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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
	client, err := BuildMtlsClient(cert, base)
	if err != nil {
		t.Fatalf("BuildMtlsClient error: %v", err)
	}
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

// TestBuildMtlsClientUsesDefaultTransportWhenUnconfigured covers the base clients that carry no
// network path to lose: no client at all, and an *http.Client with no Transport (which net/http
// would itself serve from http.DefaultTransport). Both must still yield a usable transport carrying
// the binding certificate.
func TestBuildMtlsClientUsesDefaultTransportWhenUnconfigured(t *testing.T) {
	cert := tls.Certificate{Certificate: [][]byte{{0x01, 0x02, 0x03}}}
	var typedNil *http.Client
	for _, test := range []struct {
		desc string
		base HTTPClient
	}{
		{desc: "nil base", base: nil},
		{desc: "typed-nil *http.Client base", base: typedNil},
		{desc: "nil transport", base: &http.Client{}},
	} {
		t.Run(test.desc, func(t *testing.T) {
			client, err := BuildMtlsClient(cert, test.base)
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
		})
	}
}

// TestBuildMtlsClientRejectsOpaqueTransport replaces the old test that pinned a silent fallback to
// http.DefaultTransport. A wrapper this package cannot introspect may be enforcing mandatory proxy
// routing, certificate pinning, auditing, request signing or egress policy; swapping it for the
// process default would send the one request that carries a client credential outside all of them.
// Both shapes must now fail, and the error must name the option that resolves it.
func TestBuildMtlsClientRejectsOpaqueTransport(t *testing.T) {
	cert := tls.Certificate{Certificate: [][]byte{{0x01, 0x02, 0x03}}}
	for _, test := range []struct {
		desc string
		base HTTPClient
	}{
		{desc: "non-http.Client base", base: &recordingClient{}},
		{desc: "custom RoundTripper", base: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, nil })}},
	} {
		t.Run(test.desc, func(t *testing.T) {
			client, err := BuildMtlsClient(cert, test.base)
			if err == nil {
				t.Fatal("BuildMtlsClient silently fell back to the default transport, want an error")
			}
			if client != nil {
				t.Errorf("BuildMtlsClient returned a client (%T) alongside an error", client)
			}
			if !strings.Contains(err.Error(), "WithMtlsHTTPClient") {
				t.Errorf("error does not name WithMtlsHTTPClient: %v", err)
			}
		})
	}
}

// TestMtlsClientPropagatesBuildError pins that the failure reaches the caller of a token request
// rather than being swallowed into a cached client.
func TestMtlsClientPropagatesBuildError(t *testing.T) {
	c := &Client{client: &recordingClient{}}
	cert := &tls.Certificate{Certificate: [][]byte{{0x77}}, PrivateKey: testKey}
	if _, err := c.mtlsClient(cert); err == nil {
		t.Fatal("mtlsClient with an opaque base client = nil error, want an error")
	} else if !strings.Contains(err.Error(), "WithMtlsHTTPClient") {
		t.Errorf("error does not name WithMtlsHTTPClient: %v", err)
	}
	c.mtlsMu.Lock()
	size := len(c.mtlsClients)
	c.mtlsMu.Unlock()
	if size != 0 {
		t.Errorf("cache holds %d entries after a failed build, want 0", size)
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
	client, err := BuildMtlsClient(tls.Certificate{Certificate: [][]byte{{0x01}}}, base)
	if err != nil {
		t.Fatalf("BuildMtlsClient error: %v", err)
	}
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
	client, err := BuildMtlsClient(tls.Certificate{Certificate: [][]byte{{0x01}}}, base)
	if err != nil {
		t.Fatalf("BuildMtlsClient error: %v", err)
	}
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
// goroutines racing on the same thumbprint must all end up with the same client, and no client may
// be closed: they all came from the caller's factory, which owns their lifetime. Closing a race
// loser here is what breaks a memoizing factory, where the "loser" is the same object as the winner.
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
		if n := rc.closeCount(); n != 0 {
			t.Errorf("a factory-supplied client was closed %d times, want 0", n)
		}
	}
}

// TestMtlsClientCacheCapClears pins the cap-then-clear policy, which is exact parity with MSAL .NET's
// SimpleHttpClientFactory.CheckAndManageCache (clear at 1000, no eviction ordering, no disposal).
//
// The clients here all came from a caller-supplied factory, so none of them may be closed: a factory
// is free to memoize, in which case every entry in the cache - and the newcomer that just tripped
// the cap - is the same *http.Client, and "closing the evicted entries" would tear down the pool of
// the client being returned. MSAL closes only pools it created; see
// TestMtlsClientCacheCapClosesOnlyMsalBuiltClients for that half.
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
	for i, rc := range built {
		if n := rc.closeCount(); n != 0 {
			t.Fatalf("factory-supplied client %d had CloseIdleConnections called %d times, want 0: MSAL must not close a pool the caller owns", i, n)
		}
	}
}

// TestMtlsClientCacheCapClosesOnlyMsalBuiltClients is the other half of the ownership rule: a client
// MSAL built (no factory installed) still has its keep-alive sockets released when the cap clears it,
// because nothing else in the process holds a reference to reclaim them. The cache is seeded directly
// so both provenances can be observed with recording clients.
func TestMtlsClientCacheCapClosesOnlyMsalBuiltClients(t *testing.T) {
	msalBuilt := &recordingClient{}
	callerOwned := &recordingClient{}

	c := &Client{}
	c.mtlsMu.Lock()
	c.mtlsClients = map[string]mtlsCacheEntry{
		"msal-built":   {client: msalBuilt, owned: true},
		"caller-owned": {client: callerOwned, owned: false},
	}
	for i := 0; len(c.mtlsClients) < maxMtlsClients; i++ {
		c.mtlsClients["filler-"+strconv.Itoa(i)] = mtlsCacheEntry{client: &recordingClient{}, owned: true}
	}
	c.mtlsMu.Unlock()

	// No factory, so this builds through BuildMtlsClient and trips the cap.
	cert := &tls.Certificate{Certificate: [][]byte{{0x91, 0x92}}, PrivateKey: testKey}
	if _, err := c.mtlsClient(cert); err != nil {
		t.Fatalf("mtlsClient failed: %v", err)
	}

	c.mtlsMu.Lock()
	size := len(c.mtlsClients)
	c.mtlsMu.Unlock()
	if size != 1 {
		t.Fatalf("cache holds %d entries after the cap was tripped, want 1", size)
	}
	if n := msalBuilt.closeCount(); n != 1 {
		t.Errorf("MSAL-built client had CloseIdleConnections called %d times, want 1", n)
	}
	if n := callerOwned.closeCount(); n != 0 {
		t.Errorf("caller-supplied client had CloseIdleConnections called %d times, want 0", n)
	}
}

// TestMtlsClientRaceLoserKeepsCallerClientOpen covers the other eviction path. A factory that
// memoizes returns the same client to both racers, so the loser closing "its" client would close the
// exact object it is about to hand back. The interleaving is forced by publishing the winner from
// inside the factory, which mtlsClient invokes outside mtlsMu.
func TestMtlsClientRaceLoserKeepsCallerClientOpen(t *testing.T) {
	cert := &tls.Certificate{Certificate: [][]byte{{0x64, 0x65}}, PrivateKey: testKey}
	sum := sha256.Sum256(cert.Certificate[0])
	key := base64.RawURLEncoding.EncodeToString(sum[:])

	shared := &recordingClient{}
	c := &Client{}
	c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient {
		c.mtlsMu.Lock()
		if c.mtlsClients == nil {
			c.mtlsClients = map[string]mtlsCacheEntry{}
		}
		if _, ok := c.mtlsClients[key]; !ok {
			c.mtlsClients[key] = mtlsCacheEntry{client: shared}
		}
		c.mtlsMu.Unlock()
		return shared
	})

	got, err := c.mtlsClient(cert)
	if err != nil {
		t.Fatalf("mtlsClient failed: %v", err)
	}
	if got != shared {
		t.Fatalf("mtlsClient returned %p, want the published client %p", got, shared)
	}
	if n := shared.closeCount(); n != 0 {
		t.Errorf("the client returned to the caller had CloseIdleConnections called %d times, want 0", n)
	}
}

// TestMtlsClientDiscardsClientFromRetiredFactory pins the publish race. mtlsClient reads the factory
// under mtlsMu, builds outside it, then retakes the lock to publish; SetMtlsClientFactory landing in
// that window nils the cache precisely so clients cannot mix factories, and without a generation
// check the in-flight goroutine would seed the fresh map with a client from the factory that was just
// retired and serve it indefinitely.
//
// The interleaving is deterministic: the first factory swaps itself out while it is being invoked,
// which is legal because mtlsClient calls factories outside the lock.
func TestMtlsClientDiscardsClientFromRetiredFactory(t *testing.T) {
	cert := &tls.Certificate{Certificate: [][]byte{{0x71, 0x72}}, PrivateKey: testKey}
	retired := &recordingClient{}
	current := &recordingClient{}

	c := &Client{}
	var swapped bool
	c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient {
		if !swapped {
			swapped = true
			c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient { return current })
			return retired
		}
		t.Error("the retired factory was consulted again after being replaced")
		return retired
	})

	got, err := c.mtlsClient(cert)
	if err != nil {
		t.Fatalf("mtlsClient failed: %v", err)
	}
	if got != current {
		t.Fatalf("mtlsClient returned a client from the retired factory")
	}
	c.mtlsMu.Lock()
	cached := c.mtlsClients
	c.mtlsMu.Unlock()
	if len(cached) != 1 {
		t.Fatalf("cache holds %d entries, want 1", len(cached))
	}
	for _, entry := range cached {
		if entry.client != current {
			t.Error("the cache published a client built by the retired factory")
		}
	}
	// The discarded client came from the caller's factory, so MSAL must not close it either.
	if n := retired.closeCount(); n != 0 {
		t.Errorf("discarded caller-supplied client had CloseIdleConnections called %d times, want 0", n)
	}
}

// TestSetMtlsClientFactoryClosesDiscardedClients covers the reset path: replacing the factory drops
// the whole cache, and those clients' pooled sockets must be released.
//
// This is the one place MSAL closes a client it did not build, and deliberately so. It is an
// explicit, caller-initiated lifecycle event - the application is retiring the factory that produced
// these clients - rather than the invisible cache housekeeping in mtlsClient, and nothing is
// published afterwards, so unlike those paths it can never close a client it is about to return.
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
