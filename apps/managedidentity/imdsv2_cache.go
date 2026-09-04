// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"time"
)

// certCacheEntry is a cached binding certificate together with the key that
// proves possession of it.
type certCacheEntry struct {
	cert *bindingCertificate
}

// mintGate serializes issuance for one identity. It is a channel rather than a
// mutex because a caller waiting for it has to stay cancellable: minting makes
// two network calls, so a caller whose context expires while queued behind
// another must be able to give up.
type mintGate struct {
	ch chan struct{}
	// waiters counts everyone holding or queued for the gate, so it can be
	// dropped from the map once the last one is done rather than accumulating
	// an entry per identity the process ever used.
	waiters int
}

// bindingCertCache caches issued binding certificates for the lifetime of the
// process. IMDS rate limits credential issuance, and a certificate is valid for
// far longer than a single token, so re-issuing per token request would be both
// slow and liable to throttling.
//
// The cache is process-wide because the underlying CNG key container is
// process-wide: two Client values configured for the same identity would
// otherwise race to overwrite each other's key.
type bindingCertCache struct {
	mu      sync.Mutex
	entries map[string]*certCacheEntry
	// gates hold minting to one caller per identity. Two different identities
	// do not block each other, which a single lock around issuance would make
	// them do: minting is two network round trips, so an unrelated identity
	// would wait out both. MSAL .NET keys its gates the same way, with
	// KeyedSemaphorePool in MtlsCertificateCache.
	gates map[string]*mintGate
	// forceMint marks identities whose certificate the service rejected. It is
	// what stops the caches from answering between the eviction and the next
	// mint: without it a reader that already passed the eviction point could
	// put the rejected certificate back, or read it again from the store.
	// MSAL .NET keeps the same flag, as MtlsBindingCache._forceMint.
	forceMint map[string]struct{}
	persisted persistentCertCache
}

var certCache = newBindingCertCache()

func newBindingCertCache() *bindingCertCache {
	return &bindingCertCache{
		entries:   map[string]*certCacheEntry{},
		gates:     map[string]*mintGate{},
		forceMint: map[string]struct{}{},
		persisted: newPersistentCertCache(),
	}
}

// cacheKey identifies a binding certificate by the identity the client was
// configured for and whether it was attested.
//
// The configured identity is used rather than the client ID IMDS reports,
// because this key has to be computable before any network call: it is what
// lets a cached token be found without contacting IMDS at all. The reported
// client ID is still checked against the cached certificate before it is
// reused, so an identity reassignment is caught.
//
// Attested and non-attested certificates are deliberately not interchangeable:
// a resource that requires attestation must not be handed a certificate that
// was issued without it, so the flag is part of the key rather than a field on
// the entry.
func cacheKey(id ID, attested bool) string {
	att := "0"
	if attested {
		att = "1"
	}
	return identityKey(id) + "#att=" + att
}

// identityKey renders the configured managed identity as a stable string.
//
// It is the base of the alias a persisted certificate is filed under, so it is
// the value MSAL .NET uses rather than one of this library's choosing: the two
// write the same name into the same store, which is what lets either of them
// reuse a certificate the other issued. MSAL .NET takes the configured identity
// verbatim, and names the system-assigned identity with the constant reproduced
// here. The alias itself is cacheKey - this value with the attestation tag
// appended - which is what MSAL .NET's GetMtlsCertCacheKey builds and hands to
// its persistent cache.
//
// A client ID and an object ID are both GUIDs, so two clients configured with
// the same string but different kinds share an alias. That is safe because the
// reported client ID is compared against the certificate before it is reused,
// and a mismatch mints a new one.
func identityKey(id ID) string {
	switch t := id.(type) {
	case UserAssignedClientID:
		return string(t)
	case UserAssignedObjectID:
		return string(t)
	case UserAssignedResourceID:
		return string(t)
	default:
		// Constants.ManagedIdentityDefaultClientId in MSAL .NET.
		return "system_assigned_managed_identity"
	}
}

// get returns a cached certificate if one is present. The returned certificate
// carries a reference the caller must release with Close, so that a concurrent
// evict cannot release the key while it is in use.
func (c *bindingCertCache) get(key string) (*bindingCertificate, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, forced := c.forceMint[key]; forced {
		return nil, false
	}
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	entry.cert.retain()
	return entry.cert, true
}

// evict drops a certificate from every cache and marks the identity so nothing
// can serve the evicted certificate again before a new one is minted.
func (c *bindingCertCache) evict(key string) {
	c.mu.Lock()
	c.forceMint[key] = struct{}{}
	if entry, ok := c.entries[key]; ok {
		_ = entry.cert.Close()
		delete(c.entries, key)
	}
	persisted := c.persisted
	c.mu.Unlock()
	persisted.deleteAll(key)
}

// dropEntry removes cert from the cache, but only if it is still the entry
// stored under key. A concurrent mint may already have replaced it, and
// dropping the replacement would throw away a certificate that is fine.
func (c *bindingCertCache) dropEntry(key string, cert *bindingCertificate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok && entry.cert == cert {
		_ = entry.cert.Close()
		delete(c.entries, key)
	}
}

// clear drops every cached certificate. It exists so tests do not leak state
// between cases.
func (c *bindingCertCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		_ = entry.cert.Close()
		delete(c.entries, key)
	}
	for key := range c.forceMint {
		delete(c.forceMint, key)
	}
}

// enter blocks until this caller is the only one minting for key.
func (c *bindingCertCache) enter(ctx context.Context, key string) error {
	c.mu.Lock()
	gate, ok := c.gates[key]
	if !ok {
		gate = &mintGate{ch: make(chan struct{}, 1)}
		c.gates[key] = gate
	}
	gate.waiters++
	c.mu.Unlock()

	select {
	case gate.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		c.releaseWaiter(key)
		return ctx.Err()
	}
}

// leave releases the gate taken by enter.
func (c *bindingCertCache) leave(key string) {
	c.mu.Lock()
	gate, ok := c.gates[key]
	c.mu.Unlock()
	if !ok {
		return
	}
	<-gate.ch
	c.releaseWaiter(key)
}

func (c *bindingCertCache) releaseWaiter(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if gate, ok := c.gates[key]; ok {
		gate.waiters--
		if gate.waiters <= 0 {
			delete(c.gates, key)
		}
	}
}

// usable returns a cached certificate that is still fit to bind a token to.
//
// The validity checks run outside the lock because the orphan check talks to
// the key provider, and holding the cache lock across an operating system call
// would serialize every identity behind it.
func (c *bindingCertCache) usable(key, clientID string, provider keyProvider) (*bindingCertificate, bool) {
	cert, ok := c.get(key)
	if !ok {
		return nil, false
	}
	if cert.ClientID == clientID && !needsRefresh(cert) && !isOrphaned(cert, provider) {
		return cert, true
	}
	c.dropEntry(key, cert)
	_ = cert.Close()
	return nil, false
}

// restore promotes a certificate from the operating system store into memory.
//
// The store holds the certificate but not the key: the key lives in a CNG
// container under a fixed name, so it is reopened here and paired with the
// certificate through the same public key comparison a freshly issued
// certificate goes through. A certificate that fails that comparison outlived
// the key it was issued for, which is what a reboot does to a per-boot VBS key,
// so the whole alias is cleared rather than left to fail again next time.
func (c *bindingCertCache) restore(key, clientID string, provider keyProvider) (*bindingCertificate, bool) {
	c.mu.Lock()
	_, forced := c.forceMint[key]
	persisted := c.persisted
	c.mu.Unlock()
	if forced {
		return nil, false
	}

	stored, ok := persisted.read(key)
	if !ok {
		return nil, false
	}
	// A certificate issued to a different identity than the one IMDS now
	// reports is not this machine's credential any more.
	if stored.ClientID != clientID {
		persisted.deleteAll(key)
		return nil, false
	}

	bound, err := provider.getOrCreateKey(bindingKeyName)
	if err != nil {
		return nil, false
	}
	if err := requireKeyGuard(bound); err != nil {
		_ = bound.Close()
		return nil, false
	}
	if err := certificateMatchesKey(stored.Leaf, bound); err != nil {
		_ = bound.Close()
		persisted.deleteAll(key)
		return nil, false
	}

	cert := newBindingCertificate(stored.DER, stored.Leaf, bound, certificateRequestResponse{
		ClientID:                   stored.ClientID,
		TenantID:                   stored.TenantID,
		MtlsAuthenticationEndpoint: stored.Endpoint,
	})
	c.adopt(key, cert)
	return cert, true
}

// adopt stores cert under key and returns with the caller still holding a
// reference of its own.
func (c *bindingCertCache) adopt(key string, cert *bindingCertificate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.entries[key]; ok {
		_ = existing.cert.Close()
	}
	c.entries[key] = &certCacheEntry{cert: cert}
	cert.retain()
	delete(c.forceMint, key)
}

// isOrphaned reports whether a cached certificate no longer matches the key
// currently in the CNG container.
//
// A VBS key does not survive events that reset the isolated container, and the
// container can also be recreated out from under the process. When that
// happens the cached certificate still parses and still looks valid, but the
// private key behind it is gone, so the TLS handshake fails in a way that is
// hard to attribute. Comparing the public keys detects it up front.
//
// The check runs on every read rather than being cached for an interval. It is
// not free - it opens the provider, opens the key, proves the key can sign with
// a real RSA-2048 operation inside the VBS trustlet, and exports two public
// blobs - but MSAL .NET revalidates on every cache read too
// (ImdsV2ManagedIdentitySource's cached-certificate path calls
// IsKeyGuardProtected and re-derives the key each time), and the global
// token-request gate now serializes acquisitions, so a service taking a token
// per inbound request no longer multiplies this cost across concurrent
// requests. Trusting a stale healthy answer would let a certificate whose key
// vanished mid-window reach the handshake, which is exactly the failure this
// function exists to prevent.
func isOrphaned(cert *bindingCertificate, provider keyProvider) bool {
	current, err := provider.getOrCreateKey(bindingKeyName)
	if err != nil {
		// The key cannot be reached at all, so the cached certificate is not
		// usable either.
		return true
	}
	defer func() { _ = current.Close() }()
	return certificateMatchesKey(cert.Leaf, current) != nil
}

// bindingCertRefreshWindow is how long before its expiry a cached binding
// certificate stops being reused.
//
// The window is a day rather than a few minutes because the access token
// outlives the request that fetched it. Entra issues managed identity tokens
// with roughly a day of life and binds them to this certificate, so a
// certificate that expires first leaves the caller holding a token it cannot
// spend: the resource rejects the TLS handshake, and nothing in the token
// itself says why. Refusing to bind a new token to a certificate with less
// than a token's lifetime left keeps the certificate outliving every token
// issued against it.
//
// This is the window MSAL .NET applies, as
// CertificateCacheEntry.MinRemainingLifetime, for the same reason.
const bindingCertRefreshWindow = 24 * time.Hour

// needsRefresh reports whether a cached certificate is at or past its refresh
// window and should be re-minted rather than reused.
func needsRefresh(cert *bindingCertificate) bool {
	if cert == nil || cert.Leaf == nil || cert.Leaf.NotAfter.IsZero() {
		return false
	}
	return !cert.Leaf.NotAfter.After(now().Add(bindingCertRefreshWindow))
}

// getBindingCertificate returns a binding certificate for the identity IMDS
// reports, issuing a new one only when the cache cannot supply a usable one.
//
// The returned certificate carries a reference the caller must release with
// Close.
func (v imdsV2) getBindingCertificate(ctx context.Context, attested bool) (*bindingCertificate, string, error) {
	if !platformSupportsMtlsPoP() {
		return nil, "", ErrMtlsNotSupportedForPlatform
	}
	correlationID := newCorrelationID()
	key := cacheKey(v.miType, attested)

	// Leg 1 runs on every acquisition, even on a cache hit. It is what names the
	// identity, so it is also what detects that the identity assigned to this
	// VM changed underneath a cached certificate.
	metadata, err := v.getCsrMetadata(ctx, correlationID)
	if err != nil {
		return nil, "", err
	}

	if cert, ok := certCache.usable(key, metadata.ClientID, v.keyProvider); ok {
		return cert, key, nil
	}

	// Past this point a certificate is going to be issued unless another caller
	// is already doing it, so the rest runs one caller at a time per identity.
	if err := certCache.enter(ctx, key); err != nil {
		return nil, "", err
	}
	defer certCache.leave(key)

	// Whoever held the gate may have minted the certificate this caller wanted.
	if cert, ok := certCache.usable(key, metadata.ClientID, v.keyProvider); ok {
		return cert, key, nil
	}

	// A previous run of this or any other MSAL on the machine may have left a
	// usable certificate behind, which is worth far more than a round trip: it
	// is what keeps a restarting fleet from being throttled by IMDS.
	if cert, ok := certCache.restore(key, metadata.ClientID, v.keyProvider); ok {
		return cert, key, nil
	}

	cert, err := v.issueBindingCertificate(ctx, correlationID, metadata, attested)
	if err != nil {
		return nil, "", err
	}
	// A certificate that is already inside the refresh window is used for this
	// request but not cached: a later caller would only reject it on read, so
	// storing it would hold a key handle open for nothing. MSAL .NET applies
	// the same rule on write, in InMemoryCertificateCache.Set.
	if needsRefresh(cert) {
		return cert, key, nil
	}
	// The cache takes over the reference newBindingCertificate created; the
	// caller gets one of its own.
	certCache.adopt(key, cert)
	certCache.persist(key, cert)
	return cert, key, nil
}

// persist writes a newly issued certificate to the operating system store so a
// restart can reuse it. Failure is not reported: the certificate is already
// usable, and persistence only saves a future round trip.
func (c *bindingCertCache) persist(key string, cert *bindingCertificate) {
	c.mu.Lock()
	persisted := c.persisted
	c.mu.Unlock()
	persisted.write(key, cert)
}

// issueBindingCertificate mints a key and exchanges a CSR for a certificate.
// The caller holds the cache lock.
func (v imdsV2) issueBindingCertificate(ctx context.Context, correlationID string, metadata csrMetadata, attested bool) (*bindingCertificate, error) {
	key, err := v.keyProvider.getOrCreateKey(bindingKeyName)
	if err != nil {
		return nil, err
	}
	// A software key would produce a token shaped like a bound token while
	// offering none of the guarantees, so this refuses rather than downgrades.
	if err := requireKeyGuard(key); err != nil {
		_ = key.Close()
		return nil, err
	}

	csr, err := createCSR(key.Signer, metadata.ClientID, metadata.TenantID, metadata.CuID)
	if err != nil {
		_ = key.Close()
		return nil, err
	}

	// Attestation is attempted only when the caller opted in with
	// WithAttestationSupport(), which mirrors MSAL .NET: without its optional
	// attestation package the provider is unset and the credential request goes
	// out non-attested.
	//
	// Once the caller has opted in, a failure to attest is fatal rather than a
	// downgrade. Falling back would send a non-attested request on behalf of a
	// caller who explicitly asked for attestation, turning a missing native
	// library or an MAA policy denial into a credential that silently carries
	// fewer guarantees than the one requested.
	var attestationToken string
	if attested {
		endpoint, err := metadata.attestationURL()
		if err != nil {
			_ = key.Close()
			return nil, err
		}
		attestationToken, err = attestKeyGuardCached(ctx, endpoint, metadata.ClientID, key)
		if err != nil {
			_ = key.Close()
			return nil, err
		}
	}

	issued, err := v.issueCredential(ctx, correlationID, csr, attestationToken)
	if err != nil {
		_ = key.Close()
		return nil, err
	}

	leaf, der, err := parseIssuedCertificate(issued.Certificate)
	if err != nil {
		_ = key.Close()
		return nil, err
	}
	if err := certificateMatchesKey(leaf, key); err != nil {
		_ = key.Close()
		return nil, err
	}

	return newBindingCertificate(der, leaf, key, issued), nil
}

// parseIssuedCertificate decodes the base64 DER IMDS returned.
func parseIssuedCertificate(encoded string) (*x509.Certificate, []byte, error) {
	der, err := decodeCertificate(encoded)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("managedidentity: parsing the issued certificate: %w", err)
	}
	return leaf, der, nil
}
