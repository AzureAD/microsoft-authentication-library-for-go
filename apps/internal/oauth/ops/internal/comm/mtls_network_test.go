// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package comm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// assertionBody stands in for the form a real token request posts. urlFormCall always supplies a
// GetBody, so a 307 or 308 replays this verbatim to whatever host the Location header names.
const assertionBody = "grant_type=client_credentials&client_assertion=SECRET.CLIENT.ASSERTION"

// newBindingCert returns a self-signed client certificate usable in a real handshake. cn is what the
// server-side assertions match on, so each certificate in a test is identifiable on the wire.
func newBindingCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key for %s: %v", cn, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate for %s: %v", cn, err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsHit is what a TLS server observed about one request: the body it was handed, the client
// certificate presented during the handshake, and whether the TLS session was resumed.
type tlsHit struct {
	body     string
	clientCN string
	numCerts int
	resumed  bool
}

type tlsRecorder struct {
	mu   sync.Mutex
	hits []tlsHit
}

// handler records every request and answers with status, optionally redirecting to location.
func (r *tlsRecorder) handler(status int, location string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		hit := tlsHit{}
		if b, err := io.ReadAll(req.Body); err == nil {
			hit.body = string(b)
		}
		if req.TLS != nil {
			hit.resumed = req.TLS.DidResume
			hit.numCerts = len(req.TLS.PeerCertificates)
			if hit.numCerts > 0 {
				hit.clientCN = req.TLS.PeerCertificates[0].Subject.CommonName
			}
		}
		r.mu.Lock()
		r.hits = append(r.hits, hit)
		r.mu.Unlock()
		if location != "" {
			w.Header().Set("Location", location)
		}
		w.WriteHeader(status)
	}
}

func (r *tlsRecorder) snapshot() []tlsHit {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]tlsHit(nil), r.hits...)
}

// startTLSServer brings up an HTTPS test server that requests, but does not require, a client
// certificate. RequestClientCert is deliberate: the handshake still completes when the client offers
// nothing, so a test can tell "presented no certificate" apart from "the connection was refused".
// maxVersion of 0 leaves Go's default in place.
func startTLSServer(t *testing.T, h http.Handler, maxVersion uint16) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MaxVersion: maxVersion}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func rootsFor(servers ...*httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, s := range servers {
		pool.AddCert(s.Certificate())
	}
	return pool
}

// postAssertion issues the shape of request urlFormCall builds: a POST carrying a credential, with a
// GetBody that lets net/http replay it across a 307 or 308.
func postAssertion(t *testing.T, client *http.Client, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(assertionBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	if req.GetBody == nil {
		t.Fatal("the test request has no GetBody, so it would not reproduce the replay urlFormCall enables")
	}
	return client.Do(req)
}

// TestBuildMtlsClientRefusesRedirectsByDefault is the 307/308 regression test. Preserving the
// caller's CheckRedirect is not enough on its own: almost nobody sets it, and copying nil across
// leaves Go's default, which follows up to ten redirects and - because the request carries a GetBody
// - replays the POST body verbatim. The target would then receive the client assertion and be
// offered the binding certificate during the handshake. The redirect target must not be reached at
// all.
func TestBuildMtlsClientRefusesRedirectsByDefault(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			target := &tlsRecorder{}
			targetSrv := startTLSServer(t, target.handler(http.StatusOK, ""), 0)
			origin := &tlsRecorder{}
			originSrv := startTLSServer(t, origin.handler(status, targetSrv.URL+"/redirected"), 0)

			base := &http.Client{Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: rootsFor(targetSrv, originSrv)},
			}}
			client, err := BuildMtlsClient(newBindingCert(t, "binding-cert"), base)
			if err != nil {
				t.Fatalf("BuildMtlsClient error: %v", err)
			}

			resp, err := postAssertion(t, client, originSrv.URL)
			if resp != nil {
				resp.Body.Close()
			}
			if err == nil {
				t.Fatalf("the client followed the %d redirect instead of refusing it", status)
			}
			if !strings.Contains(err.Error(), "WithMtlsHTTPClient") {
				t.Errorf("the refusal does not name WithMtlsHTTPClient: %v", err)
			}
			if n := len(origin.snapshot()); n != 1 {
				t.Fatalf("the redirecting endpoint was reached %d time(s), want 1", n)
			}
			if hits := target.snapshot(); len(hits) != 0 {
				t.Fatalf("the redirect target was reached %d time(s); it received body %q and %d client certificate(s) (CN %q) - the credential and the binding certificate leaked",
					len(hits), hits[0].body, hits[0].numCerts, hits[0].clientCN)
			}
		})
	}
}

// TestBuildMtlsClientHonorsCallerCheckRedirect covers the other half of the policy: a caller who set
// CheckRedirect has stated one, and MSAL does not silently override explicit caller configuration.
// Both directions matter - a refusing policy must surface the caller's own error rather than ours,
// and a permissive one must actually permit, which is what proves the default is a default and not a
// blanket ban.
func TestBuildMtlsClientHonorsCallerCheckRedirect(t *testing.T) {
	target := &tlsRecorder{}
	targetSrv := startTLSServer(t, target.handler(http.StatusOK, ""), 0)
	origin := &tlsRecorder{}
	originSrv := startTLSServer(t, origin.handler(http.StatusTemporaryRedirect, targetSrv.URL+"/redirected"), 0)
	roots := rootsFor(targetSrv, originSrv)
	cert := newBindingCert(t, "binding-cert")

	t.Run("a refusing policy is used", func(t *testing.T) {
		callerErr := errors.New("caller redirect policy said no")
		base := &http.Client{
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return callerErr },
		}
		client, err := BuildMtlsClient(cert, base)
		if err != nil {
			t.Fatalf("BuildMtlsClient error: %v", err)
		}
		resp, err := postAssertion(t, client, originSrv.URL)
		if resp != nil {
			resp.Body.Close()
		}
		if !errors.Is(err, callerErr) {
			t.Fatalf("error = %v, want the caller's own redirect policy error - the caller's CheckRedirect was dropped", err)
		}
	})

	t.Run("a permissive policy is used", func(t *testing.T) {
		before := len(target.snapshot())
		base := &http.Client{
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return nil },
		}
		client, err := BuildMtlsClient(cert, base)
		if err != nil {
			t.Fatalf("BuildMtlsClient error: %v", err)
		}
		resp, err := postAssertion(t, client, originSrv.URL)
		if err != nil {
			t.Fatalf("the caller's permissive redirect policy was overridden: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		hits := target.snapshot()
		if len(hits) != before+1 {
			t.Fatalf("the redirect target was reached %d time(s), want 1", len(hits)-before)
		}
		// This is exactly what the default refusal exists to prevent: a caller who opts in gets the
		// replayed credential and a client-certificate handshake at the redirect target.
		last := hits[len(hits)-1]
		if last.body != assertionBody {
			t.Errorf("the target received body %q, want the replayed %q", last.body, assertionBody)
		}
		if last.numCerts != 1 || last.clientCN != "binding-cert" {
			t.Errorf("the target saw %d client certificate(s) (CN %q), want 1 (CN binding-cert)", last.numCerts, last.clientCN)
		}
	})
}

// TestBuildMtlsClientRejectsTLSDialHooks covers both TLS dial hooks separately. http.Transport.Clone
// copies DialTLS and DialTLSContext, and net/http then runs the handshake through the hook and
// ignores TLSClientConfig - so the clone would look correctly configured while the binding
// certificate, the TLS 1.2 floor and the caller's RootCAs all go unused.
func TestBuildMtlsClientRejectsTLSDialHooks(t *testing.T) {
	cert := newBindingCert(t, "binding-cert")
	for _, test := range []struct {
		field     string
		transport *http.Transport
	}{
		{
			field: "DialTLS",
			transport: &http.Transport{DialTLS: func(network, addr string) (net.Conn, error) {
				return nil, errors.New("the caller's TLS dialer should never run")
			}},
		},
		{
			field: "DialTLSContext",
			transport: &http.Transport{DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return nil, errors.New("the caller's TLS dialer should never run")
			}},
		},
	} {
		t.Run(test.field, func(t *testing.T) {
			client, err := BuildMtlsClient(cert, &http.Client{Transport: test.transport})
			if err == nil {
				t.Fatalf("BuildMtlsClient accepted a transport with %s, so the binding certificate would never reach the handshake", test.field)
			}
			if client != nil {
				t.Errorf("BuildMtlsClient returned a client (%T) alongside an error", client)
			}
			if !strings.Contains(err.Error(), test.field) {
				t.Errorf("the error does not name %s: %v", test.field, err)
			}
			if !strings.Contains(err.Error(), "WithMtlsHTTPClient") {
				t.Errorf("the error does not name WithMtlsHTTPClient: %v", err)
			}
		})
	}
}

// TestBuildMtlsClientRejectsTLSDialHooksOnDefaultTransport closes the path that never touches the
// caller's transport at all. http.DefaultTransport is an exported package-level variable, so
// tracing, proxy-injection and test libraries can install a TLS dial hook on it process-wide. Both
// entry points that fall through to it - no configured client, and an *http.Client whose Transport
// is nil - must be checked too, or MSAL would clone a transport that silently drops the binding
// certificate through a route the caller-transport check cannot see.
//
// This test mutates process-global state. It must never call t.Parallel or run alongside anything
// that touches the default transport, and it restores the original hooks through t.Cleanup.
func TestBuildMtlsClientRejectsTLSDialHooksOnDefaultTransport(t *testing.T) {
	dt, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Skipf("http.DefaultTransport is a %T, not an *http.Transport", http.DefaultTransport)
	}
	origDialTLS, origDialTLSContext := dt.DialTLS, dt.DialTLSContext
	t.Cleanup(func() {
		dt.DialTLS, dt.DialTLSContext = origDialTLS, origDialTLSContext
	})

	cert := newBindingCert(t, "binding-cert")
	var typedNil *http.Client
	for _, hook := range []struct {
		field   string
		install func()
	}{
		{
			field: "DialTLSContext",
			install: func() {
				dt.DialTLS = nil
				dt.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return nil, errors.New("the patched default TLS dialer should never run")
				}
			},
		},
		{
			field: "DialTLS",
			install: func() {
				dt.DialTLSContext = nil
				dt.DialTLS = func(network, addr string) (net.Conn, error) {
					return nil, errors.New("the patched default TLS dialer should never run")
				}
			},
		},
	} {
		t.Run(hook.field, func(t *testing.T) {
			hook.install()
			for _, entry := range []struct {
				desc string
				base HTTPClient
			}{
				{desc: "no configured client", base: nil},
				{desc: "typed-nil client", base: typedNil},
				{desc: "client with nil Transport", base: &http.Client{}},
			} {
				t.Run(entry.desc, func(t *testing.T) {
					client, err := BuildMtlsClient(cert, entry.base)
					if err == nil {
						t.Fatalf("BuildMtlsClient cloned an http.DefaultTransport carrying %s, so the binding certificate would never reach the handshake", hook.field)
					}
					if client != nil {
						t.Errorf("BuildMtlsClient returned a client (%T) alongside an error", client)
					}
					if !strings.Contains(err.Error(), hook.field) {
						t.Errorf("the error does not name %s: %v", hook.field, err)
					}
					if !strings.Contains(err.Error(), "WithMtlsHTTPClient") {
						t.Errorf("the error does not name WithMtlsHTTPClient: %v", err)
					}
					// The caller did not configure this transport, so the message must identify the
					// shared default as the source and must not read as if they had set the hook.
					if !strings.Contains(err.Error(), "http.DefaultTransport") {
						t.Errorf("the error does not identify http.DefaultTransport as the source: %v", err)
					}
					if !strings.Contains(err.Error(), "MSAL did not configure this transport") {
						t.Errorf("the error blames the caller for a hook they did not set: %v", err)
					}
				})
			}
		})
	}

	// Restoring must leave the default transport exactly as it was found. Assert it here as well as
	// in Cleanup, so a leak is attributable to this test rather than to whatever runs next.
	dt.DialTLS, dt.DialTLSContext = origDialTLS, origDialTLSContext
	if _, err := BuildMtlsClient(cert, nil); err != nil {
		t.Fatalf("BuildMtlsClient failed after http.DefaultTransport was restored: %v", err)
	}
}

// TestBuildMtlsClientPreservesDialContext pins that the TLS dial hook rejection is scoped to the TLS
// hooks. DialContext establishes only the TCP connection - the handshake still runs against our
// TLSClientConfig - so a caller's dialer, proxy routing and DNS control must survive, which is what
// cloneBaseTransport exists to do. The request must succeed through that dialer and still present
// the binding certificate.
func TestBuildMtlsClientPreservesDialContext(t *testing.T) {
	rec := &tlsRecorder{}
	srv := startTLSServer(t, rec.handler(http.StatusOK, ""), 0)

	var mu sync.Mutex
	dialed := 0
	base := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: rootsFor(srv)},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialed++
			mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}

	client, err := BuildMtlsClient(newBindingCert(t, "binding-cert"), base)
	if err != nil {
		t.Fatalf("BuildMtlsClient rejected a plain DialContext, which does not bypass TLSClientConfig: %v", err)
	}
	resp, err := postAssertion(t, client, srv.URL)
	if err != nil {
		t.Fatalf("the request through the caller's dialer failed: %v", err)
	}
	defer resp.Body.Close()

	mu.Lock()
	n := dialed
	mu.Unlock()
	if n != 1 {
		t.Errorf("the caller's DialContext ran %d time(s), want 1", n)
	}
	hits := rec.snapshot()
	if len(hits) != 1 {
		t.Fatalf("the server saw %d request(s), want 1", len(hits))
	}
	if hits[0].numCerts != 1 || hits[0].clientCN != "binding-cert" {
		t.Errorf("the server saw %d client certificate(s) (CN %q), want 1 (CN binding-cert)", hits[0].numCerts, hits[0].clientCN)
	}
}

// TestBuildMtlsClientIsolatesSessionCachePerCertificate is the cross-certificate resumption test.
// tls.Config.Clone shallow-copies ClientSessionCache because it is an interface, so every client
// cloned from one base used to point at the same cache object. A client bound to certificate B could
// then resume a session the server had authenticated under certificate A: the TLS peer identity, the
// certificate that signed the assertion and the cache KeyID would all disagree. The run is pinned to
// TLS 1.2 so the session ticket is delivered inside the handshake and resumption is deterministic.
func TestBuildMtlsClientIsolatesSessionCachePerCertificate(t *testing.T) {
	rec := &tlsRecorder{}
	srv := startTLSServer(t, rec.handler(http.StatusOK, ""), tls.VersionTLS12)

	// One base transport, as an application configures it, carrying a session cache that every
	// clone would otherwise share.
	shared := tls.NewLRUClientSessionCache(8)
	base := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:            rootsFor(srv),
		ClientSessionCache: shared,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	}}}

	clientA, err := BuildMtlsClient(newBindingCert(t, "binding-cert-A"), base)
	if err != nil {
		t.Fatalf("BuildMtlsClient(A) error: %v", err)
	}
	clientB, err := BuildMtlsClient(newBindingCert(t, "binding-cert-B"), base)
	if err != nil {
		t.Fatalf("BuildMtlsClient(B) error: %v", err)
	}

	cacheOf := func(c *http.Client) tls.ClientSessionCache {
		return c.Transport.(*http.Transport).TLSClientConfig.ClientSessionCache
	}
	if cacheOf(clientA) == nil || cacheOf(clientB) == nil {
		t.Fatal("an mTLS client has no TLS session cache")
	}
	if cacheOf(clientA) == cacheOf(clientB) {
		t.Error("both mTLS clients share one TLS session cache")
	}
	if cacheOf(clientA) == shared || cacheOf(clientB) == shared {
		t.Error("an mTLS client kept the caller's shared session cache")
	}

	get := func(t *testing.T, c *http.Client, who string) {
		t.Helper()
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatalf("%s request failed: %v", who, err)
		}
		defer resp.Body.Close()
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatalf("%s draining the response failed: %v", who, err)
		}
	}

	get(t, clientA, "clientA")
	// Drop A's pooled sockets so B cannot reuse a live connection. The only route left to
	// resumption is a shared ticket cache.
	clientA.CloseIdleConnections()
	get(t, clientB, "clientB")

	hits := rec.snapshot()
	if len(hits) != 2 {
		t.Fatalf("the server saw %d request(s), want 2", len(hits))
	}
	if hits[0].resumed {
		t.Fatal("the first handshake resumed a session, so the test never established a fresh one")
	}
	if hits[0].clientCN != "binding-cert-A" {
		t.Fatalf("the first handshake presented CN %q, want binding-cert-A", hits[0].clientCN)
	}
	if hits[1].resumed {
		t.Errorf("the client bound to certificate B resumed a TLS session, and the server saw peer CN %q; the session cache is shared across binding certificates", hits[1].clientCN)
	}
	if hits[1].clientCN != "binding-cert-B" {
		t.Errorf("the second handshake was authenticated as CN %q, want binding-cert-B", hits[1].clientCN)
	}
}
