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
// caller's proxy, dialer and root CAs survive on mTLS token requests. When base is shaped so that
// the binding certificate cannot actually reach the handshake - an opaque http.RoundTripper, or an
// *http.Transport that owns the handshake through DialTLS/DialTLSContext - this returns an error
// naming confidential.WithMtlsHTTPClient instead of quietly rerouting the request; see
// cloneBaseTransport. Dropping the caller's transport unconditionally was a real parity gap: MSAL
// .NET's HttpManager routes through the configured IMsalHttpClientFactory on every branch and never
// builds from a hidden default.
//
// Redirects are refused unless the caller set an explicit policy; see mtlsCheckRedirect.
//
// Nothing the caller owns is mutated. http.Transport.Clone deep-copies the transport including its
// TLSClientConfig, and the copy is what the client certificate is installed on, so the caller's
// *tls.Config is neither shared nor written to.
//
// http.Client.Timeout is deliberately not carried over: every request goes through doWithClient,
// which already applies a 30 second context deadline.
func BuildMtlsClient(cert tls.Certificate, base HTTPClient) (*http.Client, error) {
	transport, err := cloneBaseTransport(base)
	if err != nil {
		return nil, err
	}
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
	// tls.Config.Clone shallow-copies ClientSessionCache, because it is an interface: every clone of
	// one base config points at the same cache object. Two clients built for different binding
	// certificates would then share tickets, and a client holding certificate B could resume a
	// session the server authenticated under certificate A. The TLS peer identity would silently
	// disagree with the certificate this client is bound to, with the assertion that certificate
	// signed, and with the KeyID the resulting token is cached under. Give every client a private
	// cache instead. mtlsClient keeps one client per certificate thumbprint, so the cache stays
	// scoped to a single identity while resumption still works for repeated calls on that identity.
	// A capacity of 0 selects Go's default.
	transport.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	return &http.Client{
		Transport:     transport,
		CheckRedirect: mtlsCheckRedirect(base),
	}, nil
}

// mtlsCheckRedirect picks the redirect policy for the mutual-TLS leg: the caller's when they set
// one, otherwise a refusal.
//
// Carrying the caller's CheckRedirect across is necessary but on its own fixes nothing, because
// almost no caller sets it. A nil policy is not "no policy" - it is Go's default, which follows up
// to 10 redirects, and urlFormCall gives every token request a GetBody, so a 307 or 308 replays the
// POST body verbatim. That body carries the client credential (client_assertion on the federated
// identity path), and the cloned transport would offer the binding certificate to whatever host the
// Location header names. A token endpoint has no legitimate reason to redirect, so inheriting Go's
// default trades a live credential and a client-certificate handshake for behavior nothing depends
// on. The default here is therefore to refuse, not to copy nil across.
//
// A caller who did set CheckRedirect has stated a policy, and MSAL does not silently override
// explicit caller configuration - the same rule cloneBaseTransport exists to honor. If that policy
// permits a redirect then the credential and the binding certificate do reach the target; owning
// redirect handling means owning that, and confidential.WithMtlsHTTPClient is the hook for callers
// who want to own the whole leg.
func mtlsCheckRedirect(base HTTPClient) func(req *http.Request, via []*http.Request) error {
	if hc, ok := base.(*http.Client); ok && hc != nil && hc.CheckRedirect != nil {
		return hc.CheckRedirect
	}
	return refuseMtlsRedirect
}

func refuseMtlsRedirect(req *http.Request, via []*http.Request) error {
	from := "the mTLS token endpoint"
	if len(via) > 0 && via[len(via)-1].URL != nil {
		from = via[len(via)-1].URL.Redacted()
	}
	return fmt.Errorf("mTLS proof-of-possession token request to %s was redirected to %s; refusing to follow it, because a 307 or 308 replays the request body carrying the client credential and the mutual-TLS handshake would present the binding certificate to the redirect target. Set CheckRedirect on the client passed to WithHTTPClient, or use WithMtlsHTTPClient, to own redirect handling on this leg", from, req.URL.Redacted())
}

// cloneBaseTransport returns a private copy of the transport mTLS requests should build on: the
// application's own transport when the binding certificate can actually reach its handshake,
// otherwise an error naming the option that resolves it.
//
// Two shapes are rejected rather than worked around.
//
// An opaque http.RoundTripper - a tracing, retry, pinning or request-signing wrapper - exposes no
// TLSClientConfig, so the binding certificate cannot be installed on it. Substituting
// http.DefaultTransport would yield a token request that works while silently leaving the caller's
// network path: mandatory proxy routing, certificate pinning, auditing, request signing and egress
// policy would all be bypassed for the one request that carries a client credential. Documenting
// that fallback does not make it safe, so this fails instead and points at WithMtlsHTTPClient,
// which is how a caller keeps ownership of this leg.
//
// An *http.Transport with DialTLS or DialTLSContext set is rejected for the same reason one layer
// down. net/http hands the entire TLS handshake to those hooks and documents that TLSClientConfig
// and TLSHandshakeTimeout are then ignored, so the binding certificate would never be offered (or
// the dialer would present a different one), and the TLS 1.2 floor BuildMtlsClient promises would
// be silently void along with the caller's RootCAs. This is the rule BuildMtlsClient already
// applies to GetClientCertificate, which overrides certificate selection; a TLS dial hook overrides
// the whole TLS stack, so unlike GetClientCertificate it cannot be neutralized on our copy - the
// certificate, the version floor and the trust anchors all go with it. That is why this is an error
// and not a warning.
//
// DialContext is deliberately not rejected. It establishes only the TCP connection - the handshake
// still runs against our TLSClientConfig - so the caller's dialer, proxy routing and DNS control
// are preserved, which is exactly what this function exists to do.
//
// A caller with no HTTP client, or an *http.Client with no Transport, gets a clone of
// http.DefaultTransport: there is no caller network path to lose. Dropping the caller's transport
// unconditionally was a real parity gap with MSAL .NET, whose HttpManager routes through the
// configured IMsalHttpClientFactory on every branch.
func cloneBaseTransport(base HTTPClient) (*http.Transport, error) {
	if !isNilClient(base) {
		hc, ok := base.(*http.Client)
		if !ok {
			return nil, fmt.Errorf("mTLS proof-of-possession cannot use the configured HTTP client: %T is not an *http.Client, so the binding certificate cannot be installed on its transport, and falling back to the default transport would route a credential-bearing token request outside any proxy, pinning, auditing or egress controls it enforces. Use WithMtlsHTTPClient to supply a client that presents the binding certificate", base)
		}
		if hc.Transport != nil {
			t, ok := hc.Transport.(*http.Transport)
			if !ok {
				return nil, fmt.Errorf("mTLS proof-of-possession cannot use the configured HTTP client: its Transport is a %T, not an *http.Transport, so the binding certificate cannot be installed on it, and falling back to the default transport would route a credential-bearing token request outside any proxy, pinning, auditing or egress controls that wrapper enforces. Use WithMtlsHTTPClient to supply a client that presents the binding certificate", hc.Transport)
			}
			if err := rejectTLSDialHooks(t); err != nil {
				return nil, err
			}
			return t.Clone(), nil
		}
	}
	if t, ok := http.DefaultTransport.(*http.Transport); ok && t != nil {
		return t.Clone(), nil
	}
	return &http.Transport{}, nil
}

// rejectTLSDialHooks fails when the caller's transport establishes TLS itself. http.Transport.Clone
// copies DialTLSContext and DialTLS, and net/http then uses the hook instead of TLSClientConfig, so
// a clone that looks correctly configured would hand the binding certificate, the TLS 1.2 floor and
// the caller's RootCAs to code that ignores all three.
func rejectTLSDialHooks(t *http.Transport) error {
	hook := ""
	switch {
	case t.DialTLSContext != nil:
		hook = "DialTLSContext"
	case t.DialTLS != nil:
		hook = "DialTLS"
	default:
		return nil
	}
	return fmt.Errorf("mTLS proof-of-possession cannot use the configured HTTP client: its *http.Transport sets %s, and net/http then establishes TLS through that hook and ignores TLSClientConfig, so the binding certificate would never be offered (or a different one would be) and the TLS 1.2 minimum, RootCAs and TLSHandshakeTimeout would all be silently dropped. Use WithMtlsHTTPClient to supply a client that presents the binding certificate", hook)
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
		built, err := BuildMtlsClient(*cert, base)
		if err != nil {
			return nil, err
		}
		client = built
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
