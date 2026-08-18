// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package comm

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"reflect"
)

// maxMtlsClients caps the per-certificate mTLS client cache. Each entry owns its own connection
// pool, so an unbounded map leaks sockets once rotating or per-call binding certificates are in
// play. On overflow the whole cache is cleared rather than evicted in some order, which is exactly
// what MSAL .NET does (SimpleHttpClientFactory.CheckAndManageCache clears at 1000 entries) and
// avoids carrying an LRU for a map that holds a single entry in the common case.
const maxMtlsClients = 1000

// MtlsClientFactory optionally builds an HTTPClient whose transport presents cert as the client
// certificate during the mutual-TLS handshake. It is the documented override hook
// (confidential.WithMtlsHTTPClient) for callers who must own the TLS handshake themselves. When
// unset, MSAL auto-builds and caches a client per certificate.
type MtlsClientFactory func(cert tls.Certificate) HTTPClient

// SetMtlsClientFactory installs a custom factory for building mTLS clients. It is intended to be
// called during construction, before any concurrent token calls. The assignment is guarded by mtlsMu
// (paired with the read in mtlsClient) and resets the per-certificate client cache so cached clients
// can't mix factories. The discarded clients are asked to close their idle connections, because Go's
// http.Transport holds keep-alive sockets that nothing else will reclaim.
func (c *Client) SetMtlsClientFactory(factory MtlsClientFactory) {
	c.mtlsMu.Lock()
	discarded := c.mtlsClients
	c.mtlsFactory = factory
	c.mtlsClients = nil
	c.mtlsMu.Unlock()

	// Outside the lock: CloseIdleConnections on a caller-supplied client is arbitrary code that may
	// call back into this Client, and mtlsMu is a plain sync.Mutex.
	for _, client := range discarded {
		closeIdleConnections(client)
	}
}

// BuildMtlsClient returns an *http.Client whose transport presents cert as the client certificate
// during the TLS handshake and enforces a TLS 1.2 minimum.
//
// base is the HTTP client the application configured (confidential.WithHTTPClient). When it is an
// *http.Client whose Transport is an *http.Transport, that transport is what gets cloned, so the
// caller's proxy, dialer, root CAs and tracing survive on mTLS token requests. Cloning
// http.DefaultTransport is only the fallback for a transport that can't be identified. Dropping the
// caller's transport unconditionally was a real parity gap: MSAL .NET's HttpManager routes through
// the configured IMsalHttpClientFactory on every branch and never builds from a hidden default.
//
// Nothing the caller owns is mutated. http.Transport.Clone deep-copies the transport including its
// TLSClientConfig, and the copy is what the client certificate is installed on, so the caller's
// *tls.Config is neither shared nor written to.
//
// http.Client.Timeout is deliberately not carried over: every request goes through doWithClient,
// which already applies a 30 second context deadline.
func BuildMtlsClient(cert tls.Certificate, base HTTPClient) *http.Client {
	transport := cloneBaseTransport(base)
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		// Only ever raise the floor: a caller who pinned TLS 1.3 keeps it.
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	// A caller-supplied GetClientCertificate takes precedence over Certificates during the
	// handshake, so it would silently suppress the binding certificate. Clear it on our copy.
	transport.TLSClientConfig.GetClientCertificate = nil
	return &http.Client{Transport: transport}
}

// cloneBaseTransport returns a private copy of the transport mTLS requests should build on: the
// application's own transport when it can be identified, otherwise the process default.
func cloneBaseTransport(base HTTPClient) *http.Transport {
	if hc, ok := base.(*http.Client); ok && hc != nil {
		if t, ok := hc.Transport.(*http.Transport); ok && t != nil {
			return t.Clone()
		}
	}
	if t, ok := http.DefaultTransport.(*http.Transport); ok && t != nil {
		return t.Clone()
	}
	return &http.Transport{}
}

// mtlsClient returns an HTTPClient bound to cert, building and caching one per certificate thumbprint
// so repeated mTLS PoP calls reuse the same connection pool.
func (c *Client) mtlsClient(cert *tls.Certificate) (HTTPClient, error) {
	if cert == nil || len(cert.Certificate) == 0 || len(cert.Certificate[0]) == 0 {
		return nil, fmt.Errorf("mTLS proof-of-possession requires a binding certificate")
	}
	if cert.PrivateKey == nil {
		return nil, fmt.Errorf("mTLS proof-of-possession binding certificate is missing its private key")
	}
	sum := sha256.Sum256(cert.Certificate[0])
	key := base64.RawURLEncoding.EncodeToString(sum[:])

	c.mtlsMu.Lock()
	if existing, ok := c.mtlsClients[key]; ok {
		c.mtlsMu.Unlock()
		return existing, nil
	}
	factory, base := c.mtlsFactory, c.client
	c.mtlsMu.Unlock()

	// Build outside the lock. mtlsMu is a plain sync.Mutex, so a factory that calls back into this
	// Client would deadlock permanently, and a merely slow factory would serialize creation for
	// every other certificate. MSAL .NET builds outside its lock too: SimpleHttpClientFactory
	// evaluates CreateMtlsHttpClient(cert) before GetOrAdd is entered.
	var client HTTPClient
	if factory != nil {
		client = factory(*cert)
	} else {
		client = BuildMtlsClient(*cert, base)
	}
	if isNilClient(client) {
		return nil, fmt.Errorf("mTLS proof-of-possession client factory returned a nil client")
	}

	var discarded []HTTPClient
	c.mtlsMu.Lock()
	if existing, ok := c.mtlsClients[key]; ok {
		// Another goroutine won the race while we were building. Keep the published client so
		// callers share one connection pool, and drop ours.
		c.mtlsMu.Unlock()
		closeIdleConnections(client)
		return existing, nil
	}
	if c.mtlsClients == nil {
		c.mtlsClients = map[string]HTTPClient{}
	} else if len(c.mtlsClients) >= maxMtlsClients {
		for _, dropped := range c.mtlsClients {
			discarded = append(discarded, dropped)
		}
		c.mtlsClients = map[string]HTTPClient{}
	}
	c.mtlsClients[key] = client
	c.mtlsMu.Unlock()

	for _, dropped := range discarded {
		closeIdleConnections(dropped)
	}
	return client, nil
}

// closeIdleConnections releases the keep-alive sockets a discarded mTLS client holds. Go's
// http.Transport keeps connections pooled until it is told otherwise, so dropping a client without
// this leaks them. MSAL .NET's cap-then-clear disposes nothing; this goes further because Go's
// connection pooling makes it necessary.
func closeIdleConnections(client HTTPClient) {
	if isNilClient(client) {
		return
	}
	client.CloseIdleConnections()
}

// isNilClient reports whether client is unusable: either an untyped nil interface, or an interface
// wrapping a nil pointer. The second case is what a factory written as
//
//	var c *http.Client
//	return c
//
// produces: client == nil is false because the interface carries a type, so without this check the
// value would be cached and then panic on Do. The public option
// (confidential.WithMtlsHTTPClient) returns a concrete *http.Client and normalizes nil before it
// reaches here, but in-module factories still hand over an HTTPClient interface directly, so the
// guard stays.
func isNilClient(client HTTPClient) bool {
	if client == nil {
		return true
	}
	v := reflect.ValueOf(client)
	switch v.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface, reflect.UnsafePointer:
		return v.IsNil()
	default:
		return false
	}
}
