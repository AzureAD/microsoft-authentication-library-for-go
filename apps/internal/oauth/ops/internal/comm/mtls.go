// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package comm

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/certutil"
)

// maxMtlsClients caps the per-certificate mTLS client cache. Each entry owns its own connection
// pool, so an unbounded map leaks sockets once rotating or per-call binding certificates are in
// play. On overflow the whole cache is cleared rather than evicted in some order, which is exactly
// what MSAL .NET does (SimpleHttpClientFactory.CheckAndManageCache clears at 1000 entries) and
// avoids carrying an LRU for a map that holds a single entry in the common case.
const maxMtlsClients = 1000

// MtlsClientFactory asks the configured HTTP client to wrap a base client after augment installs the
// exact binding certificate and MSAL's transport requirements. The returned client is cached per
// certificate thumbprint and may preserve middleware around the augmented transport.
type MtlsClientFactory func(augment func(*http.Client) (*http.Client, error)) (HTTPClient, error)

// mtlsCacheEntry is one cached per-certificate mTLS client plus the provenance that decides whether
// MSAL may close its idle connections.
type mtlsCacheEntry struct {
	client HTTPClient
	// owned reports whether this client was created for this cache entry. Both BuildMtlsClient and
	// MtlsClientFactory create per-certificate clients whose idle pools must be closed when dropped.
	owned bool
}

// SetMtlsClientFactory installs the configured HTTP client's mTLS factory capability. It is intended
// to be called during construction, before any concurrent token calls. The assignment is guarded by
// mtlsMu (paired with the read in mtlsClient) and resets the per-certificate client cache so cached
// clients can't mix factories. Bumping mtlsGeneration lets an mtlsClient call that is building
// outside the lock notice the swap instead of publishing a client from the previous factory into the
// fresh map.
//
// The discarded clients are asked to close their idle connections, because Go's http.Transport holds
// keep-alive sockets that nothing else will reclaim.
func (c *Client) SetMtlsClientFactory(factory MtlsClientFactory) {
	c.mtlsMu.Lock()
	discarded := c.mtlsClients
	c.mtlsFactory = factory
	c.mtlsClients = nil
	c.mtlsGeneration++
	c.mtlsMu.Unlock()

	// Outside the lock: CloseIdleConnections on a specialized client is arbitrary code that may
	// call back into this Client, and mtlsMu is a plain sync.Mutex.
	for _, entry := range discarded {
		closeIdleConnections(entry.client)
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
// naming confidential.MtlsHTTPClientFactory instead of quietly rerouting the request; see
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
// The configured http.Client.Timeout is copied exactly. Every request also goes through
// doWithClient's 30 second context fallback, so the earliest configured limit still wins.
func BuildMtlsClient(cert tls.Certificate, base HTTPClient) (*http.Client, error) {
	isolated, err := certutil.CloneTLSCertificate(&cert)
	if err != nil {
		return nil, fmt.Errorf("invalid mTLS binding certificate: %w", err)
	}
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
	transport.TLSClientConfig.Certificates = []tls.Certificate{*isolated}
	// A caller-supplied GetClientCertificate takes precedence over Certificates during the
	// handshake, so it would silently suppress the binding certificate. Clear it on our copy.
	transport.TLSClientConfig.GetClientCertificate = nil
	// tls.Config.Clone shallow-copies ClientSessionCache, because it is an interface: every clone of
	// one base config points at the same cache object. Two clients built for different binding
	// certificates would then share tickets, and a client holding certificate B could resume a
	// session the server authenticated under certificate A. The TLS peer identity would silently
	// disagree with the certificate this client is bound to, with the assertion that certificate
	// signed, and with the KeyID the resulting token is cached under. Give every client that shares
	// a cache a private one instead. mtlsClient keeps one client per certificate thumbprint, so the
	// cache stays scoped to a single identity while resumption still works for repeated calls on
	// that identity. A capacity of 0 selects Go's default.
	//
	// A nil cache is left alone. There is no cache object to share, so nothing can leak between
	// identities, and crypto/tls treats nil as "no session resumption": installing one here would
	// instead opt a caller who deliberately disabled resumption back into it on the mTLS leg.
	if transport.TLSClientConfig.ClientSessionCache != nil {
		transport.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	}
	var timeout time.Duration
	if hc, ok := base.(*http.Client); ok && hc != nil {
		timeout = hc.Timeout
	}
	return &http.Client{
		Transport:     transport,
		CheckRedirect: mtlsCheckRedirect(base),
		Timeout:       timeout,
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
// redirect handling means owning that.
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
	return fmt.Errorf("mTLS proof-of-possession token request to %s was redirected to %s; refusing to follow it, because a 307 or 308 replays the request body carrying the client credential and the mutual-TLS handshake would present the binding certificate to the redirect target. Set CheckRedirect on the *http.Client passed to WithHTTPClient, or on the base client passed to the MtlsHTTPClientFactory augmenter, to own redirect handling on this leg", from, req.URL.Redacted())
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
// that fallback does not make it safe, so this fails instead and points at
// confidential.MtlsHTTPClientFactory, which is how a wrapper keeps ownership of this leg.
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
// http.DefaultTransport: there is no caller network path to lose. That clone is checked for TLS dial
// hooks too. http.DefaultTransport is an exported package-level variable, so tracing,
// proxy-injection and test libraries can and do patch a hook onto it process-wide; cloning it
// unchecked would drop the binding certificate through a path that never touches the caller's
// transport at all. Every transport that reaches Clone here has been checked. If something replaced
// http.DefaultTransport with a type that is not an *http.Transport at all, that is an error for the
// same reason a caller-supplied wrapper is: the replacement's proxy, pinning, auditing and egress
// behavior cannot be carried onto a certificate-bearing request, and substituting a bare transport
// would discard it silently.
//
// Dropping the caller's transport unconditionally was a real parity gap with MSAL .NET, whose
// HttpManager routes through the configured IMsalHttpClientFactory on every branch.
func cloneBaseTransport(base HTTPClient) (*http.Transport, error) {
	if !isNilClient(base) {
		hc, ok := base.(*http.Client)
		if !ok {
			return nil, fmt.Errorf("mTLS proof-of-possession cannot use the configured HTTP client: %T is not an *http.Client and does not implement confidential.MtlsHTTPClientFactory, so the binding certificate cannot be installed on its transport, and falling back to the default transport would route a credential-bearing token request outside any proxy, pinning, auditing or egress controls it enforces", base)
		}
		if hc.Transport != nil {
			t, ok := hc.Transport.(*http.Transport)
			if !ok {
				return nil, fmt.Errorf("mTLS proof-of-possession cannot use the configured HTTP client: its Transport is a %T, not an *http.Transport, so the binding certificate cannot be installed on it, and falling back to the default transport would route a credential-bearing token request outside any proxy, pinning, auditing or egress controls that wrapper enforces. Pass a confidential.MtlsHTTPClientFactory to WithHTTPClient so the wrapper can preserve that transport around an MSAL-augmented base client", hc.Transport)
			}
			if t == nil {
				return nil, fmt.Errorf("mTLS proof-of-possession cannot use the configured HTTP client: its Transport is a nil *http.Transport, so the binding certificate cannot be installed on it, and falling back to the default transport would route a credential-bearing token request outside any proxy, pinning, auditing or egress controls that wrapper enforces. Pass a confidential.MtlsHTTPClientFactory to WithHTTPClient so the wrapper can preserve that transport around an MSAL-augmented base client")
			}
			if err := rejectTLSDialHooks(t, "the configured HTTP client's *http.Transport", callerHookRemedy); err != nil {
				return nil, err
			}
			return t.Clone(), nil
		}
	}
	if t, ok := http.DefaultTransport.(*http.Transport); ok && t != nil {
		if err := rejectTLSDialHooks(t, "http.DefaultTransport", defaultHookRemedy); err != nil {
			return nil, err
		}
		return t.Clone(), nil
	}
	// http.DefaultTransport is not an *http.Transport, so something in this process replaced the
	// package-level variable outright. Returning a freshly constructed transport here would look
	// safe -- it cannot carry a hook -- but it fails open in exactly the way the two caller-supplied
	// branches above refuse to: it silently discards whatever the replacement enforces (proxy
	// routing, certificate pinning, auditing, egress control) for a credential-bearing token
	// request. A bare &http.Transport{} also has no Proxy function at all, so unlike
	// http.DefaultTransport it ignores HTTP_PROXY, HTTPS_PROXY and NO_PROXY, which in a
	// proxy-required environment turns a security fallback into a connectivity failure with no
	// explanation. Fail closed and name the remedy instead.
	return nil, fmt.Errorf("mTLS proof-of-possession cannot use http.DefaultTransport because it is a %T, not an *http.Transport: something in this process replaced the package-level variable, and falling back to a freshly constructed transport would route a credential-bearing token request outside any proxy, pinning, auditing or egress controls it enforces, and would ignore HTTP_PROXY, HTTPS_PROXY and NO_PROXY. %s", http.DefaultTransport, defaultHookRemedy)
}

// Remedies for rejectTLSDialHooks. Both point at MtlsHTTPClientFactory, but only the caller-transport
// case may imply the application installed the hook: http.DefaultTransport is an exported
// package-level variable that anything in the process can patch, so MSAL must not tell a caller they
// configured something they did not.
const (
	callerHookRemedy  = "Pass a confidential.MtlsHTTPClientFactory to WithHTTPClient so it can preserve this network path around an MSAL-augmented base client"
	defaultHookRemedy = "MSAL did not configure this transport - http.DefaultTransport is an exported package-level variable and something else in this process installed the hook on it. Pass your own *http.Transport with WithHTTPClient, or pass a confidential.MtlsHTTPClientFactory that supplies a safe base client to the augmenter"
)

// rejectTLSDialHooks fails when transport establishes TLS itself. http.Transport.Clone copies
// DialTLSContext and DialTLS, and net/http then uses the hook instead of TLSClientConfig, so a clone
// that looks correctly configured would hand the binding certificate, the TLS 1.2 floor and the
// RootCAs to code that ignores all three. source names the transport and remedy tells the caller
// what to do about it, because the answer differs for a transport they configured and for a shared
// default something else in the process patched.
func rejectTLSDialHooks(t *http.Transport, source, remedy string) error {
	hook := ""
	switch {
	case t.DialTLSContext != nil:
		hook = "DialTLSContext"
	// DialTLS is deprecated but not disabled: Transport.customDialTLS still calls it whenever
	// DialTLSContext is nil, and Transport.Clone copies it. Detecting the hook therefore means
	// reading the deprecated field, and not reading it would reintroduce exactly the bypass this
	// function exists to prevent.
	case t.DialTLS != nil: //nolint:staticcheck // SA1019: read to reject the deprecated hook, not to use it.
		hook = "DialTLS"
	default:
		return nil
	}
	return fmt.Errorf("mTLS proof-of-possession cannot use %s because it sets %s: net/http then establishes TLS through that hook and ignores TLSClientConfig, so the binding certificate would never be offered (or a different one would be) and the TLS 1.2 minimum, RootCAs and TLSHandshakeTimeout would all be silently dropped. %s", source, hook, remedy)
}

// buildMtlsClientFromFactory validates the synchronous augmentation contract and returns the
// middleware-capable client the configured HTTP client created for one certificate snapshot.
func buildMtlsClientFromFactory(factory MtlsClientFactory, cert tls.Certificate) (HTTPClient, error) {
	var (
		mu             sync.Mutex
		augmentCalls   int
		augmentErr     error
		augmented      *http.Client
		factoryDone    bool
		lateInvocation = errors.New("mTLS HTTP client factory called augment after NewMtlsClient returned; augment must be called exactly once and synchronously")
	)
	augment := func(base *http.Client) (*http.Client, error) {
		mu.Lock()
		defer mu.Unlock()

		if factoryDone {
			return nil, lateInvocation
		}
		augmentCalls++
		if augmentCalls > 1 {
			err := fmt.Errorf("mTLS HTTP client factory called augment %d times; it must call augment exactly once", augmentCalls)
			augmentErr = combineMtlsErrors(augmentErr, err)
			return nil, err
		}
		if base == nil {
			err := errors.New("mTLS HTTP client factory called augment with a nil base *http.Client; it must supply a non-nil base client")
			augmentErr = combineMtlsErrors(augmentErr, err)
			return nil, err
		}

		var err error
		augmented, err = BuildMtlsClient(cert, base)
		if err != nil {
			augmentErr = combineMtlsErrors(augmentErr, err)
		}
		return augmented, err
	}

	produced, factoryErr := factory(augment)

	mu.Lock()
	factoryDone = true
	calls := augmentCalls
	recordedAugmentErr := augmentErr
	built := augmented
	mu.Unlock()

	var contractErr error
	if calls != 1 {
		contractErr = fmt.Errorf("mTLS HTTP client factory must call augment exactly once and synchronously, got %d calls", calls)
	}
	var resultErr error
	if isNilClient(produced) {
		resultErr = errors.New("mTLS HTTP client factory returned a nil client")
	}
	if factoryErr != nil {
		factoryErr = fmt.Errorf("mTLS HTTP client factory failed: %w", factoryErr)
	}
	err := combineMtlsErrors(factoryErr, recordedAugmentErr, contractErr, resultErr)
	if err == nil {
		return produced, nil
	}

	// A failed factory never publishes a client. Prefer closing its returned wrapper so its
	// CloseIdleConnections implementation can reach the augmented pool; if it returned nil after a
	// successful augment, close that otherwise-unreachable pool directly.
	if !isNilClient(produced) {
		closeIdleConnections(produced)
	} else if built != nil {
		built.CloseIdleConnections()
	}
	return nil, err
}

// mtlsErrors retains every relevant factory/augmentation error on Go versions predating
// errors.Join. Is and As search every constituent so callers can still identify either failure.
type mtlsErrors struct {
	errs []error
}

func (e mtlsErrors) Error() string {
	messages := make([]string, len(e.errs))
	for i, err := range e.errs {
		messages[i] = err.Error()
	}
	return strings.Join(messages, "; ")
}

func (e mtlsErrors) Unwrap() error {
	return e.errs[0]
}

func (e mtlsErrors) Is(target error) bool {
	for _, err := range e.errs {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

func (e mtlsErrors) As(target interface{}) bool {
	for _, err := range e.errs {
		if errors.As(err, target) {
			return true
		}
	}
	return false
}

func combineMtlsErrors(errs ...error) error {
	combined := make([]error, 0, len(errs))
	for _, err := range errs {
		if err == nil {
			continue
		}
		if nested, ok := err.(mtlsErrors); ok {
			combined = append(combined, nested.errs...)
			continue
		}
		combined = append(combined, err)
	}
	switch len(combined) {
	case 0:
		return nil
	case 1:
		return combined[0]
	default:
		return mtlsErrors{errs: combined}
	}
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
	// Everything below works from a private deep copy. The cache key is a digest of
	// Certificate[0], and BuildMtlsClient then receives it by value -- a shallow copy that shares
	// the backing arrays. Anything still holding those arrays could rewrite them after the key was computed,
	// leaving the cached client presenting bytes that no longer match the thumbprint it is filed
	// under, and the token bound to a certificate MSAL never saw. Copying first makes the key and
	// the presented bytes derive from the same immutable snapshot.
	//
	// PrivateKey is deliberately shared rather than copied: it is the live signer that performs the
	// handshake, and a non-exportable key cannot be copied at all. Leaf is re-parsed from the copied
	// DER because its Raw fields otherwise alias the retained request certificate.
	pinned, err := certutil.CloneTLSCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("invalid mTLS binding certificate: %w", err)
	}
	sum := sha256.Sum256(pinned.Certificate[0])
	key := base64.RawURLEncoding.EncodeToString(sum[:])

	// The loop exists for the SetMtlsClientFactory race below, which discards what it built and
	// starts over with the factory that is actually installed. SetMtlsClientFactory is documented
	// as a construction-time call, so an iteration past the first is already unusual and a second
	// one requires a caller swapping factories in a tight loop while token requests run.
	for {
		c.mtlsMu.Lock()
		if existing, ok := c.mtlsClients[key]; ok {
			c.mtlsMu.Unlock()
			return existing.client, nil
		}
		factory, base, generation := c.mtlsFactory, c.client, c.mtlsGeneration
		c.mtlsMu.Unlock()

		// Build outside the lock. mtlsMu is a plain sync.Mutex, so a factory that calls back into
		// this Client would deadlock permanently, and a merely slow factory would serialize creation
		// for every other certificate. MSAL .NET builds outside its lock too: SimpleHttpClientFactory
		// evaluates CreateMtlsHttpClient(cert) before GetOrAdd is entered.
		entry := mtlsCacheEntry{owned: true}
		if factory != nil {
			entry.client, err = buildMtlsClientFromFactory(factory, *pinned)
			if err != nil {
				return nil, err
			}
		} else {
			built, err := BuildMtlsClient(*pinned, base)
			if err != nil {
				return nil, err
			}
			entry.client = built
		}

		var discarded []HTTPClient
		c.mtlsMu.Lock()
		if c.mtlsGeneration != generation {
			// SetMtlsClientFactory ran while we were building. It cleared the cache precisely so
			// clients can't mix factories, so publishing ours - built by the factory that was just
			// retired - would seed the fresh map with a stale client and serve it indefinitely.
			// Drop it and build again with the factory that is actually installed.
			c.mtlsMu.Unlock()
			discardMtlsClient(entry)
			continue
		}
		if existing, ok := c.mtlsClients[key]; ok {
			// Another goroutine won the race while we were building. Keep the published client so
			// callers share one connection pool, and drop ours.
			c.mtlsMu.Unlock()
			discardMtlsClient(entry)
			return existing.client, nil
		}
		if c.mtlsClients == nil {
			c.mtlsClients = map[string]mtlsCacheEntry{}
		} else if len(c.mtlsClients) >= maxMtlsClients {
			for _, dropped := range c.mtlsClients {
				if dropped.owned {
					discarded = append(discarded, dropped.client)
				}
			}
			c.mtlsClients = map[string]mtlsCacheEntry{}
		}
		c.mtlsClients[key] = entry
		c.mtlsMu.Unlock()

		for _, dropped := range discarded {
			closeIdleConnections(dropped)
		}
		return entry.client, nil
	}
}

// discardMtlsClient releases a client mtlsClient built but will not publish.
func discardMtlsClient(entry mtlsCacheEntry) {
	if entry.owned {
		closeIdleConnections(entry.client)
	}
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
// value would be cached and then panic on Do.
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
