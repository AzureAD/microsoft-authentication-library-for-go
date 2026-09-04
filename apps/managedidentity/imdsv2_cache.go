// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
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
	// gates hold minting to one caller per identity. They are keyed rather than
	// global because minting is two network round trips plus an attestation,
	// and a caller for one identity should not queue behind another's. MSAL
	// .NET keys its gates the same way, with KeyedSemaphorePool in
	// MtlsCertificateCache.
	//
	// Note that this does not, on its own, make two identities mint in
	// parallel: AcquireToken already holds the process-wide miTokenGate for the
	// whole acquisition, so in the ordinary flow only one identity is minting
	// at a time regardless of what this map allows. What the key buys is that
	// the gate a caller waits on is the one its own identity is using, so a
	// certificate minted for another identity never satisfies the double-check
	// below and never has to be waited out twice.
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
//
// The client ID comparison is case-insensitive. Both sides are GUIDs that have
// already been validated as such, and IMDS is not consistent about the case it
// reports them in: a certificate persisted with a lower-cased common name is
// compared against whatever leg 1 just returned. A case-sensitive comparison
// would silently re-mint on every acquisition against a rate-limited service.
func (c *bindingCertCache) usable(key, clientID string, provider keyProvider) (*bindingCertificate, bool) {
	cert, ok := c.get(key)
	if !ok {
		return nil, false
	}
	if strings.EqualFold(cert.ClientID, clientID) && !needsRefresh(cert.Leaf) && !isOrphaned(cert, provider) {
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
//
// The key is opened, never created. This is a cache read: a host with no key has
// nothing that could match the stored certificate, so creating one would change
// the machine without changing the answer.
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
	// reports is not this machine's credential any more. The comparison folds
	// case for the reason usable does: the stored value came back from a
	// certificate subject, which is lower-cased on the way in.
	if !strings.EqualFold(stored.ClientID, clientID) {
		persisted.deleteAll(key)
		return nil, false
	}

	bound, err := provider.openKey(bindingKeyName)
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
	// A stored certificate has been outside this process's control since it was
	// written, so it goes through the same checks a freshly issued one does
	// before it is trusted to carry a token.
	if err := certificateNamesIdentity(stored.Leaf, stored.ClientID); err != nil {
		_ = bound.Close()
		persisted.deleteAll(key)
		return nil, false
	}
	if err := certificateUsableForClientMtls(stored.Leaf); err != nil {
		_ = bound.Close()
		persisted.deleteAll(key)
		return nil, false
	}
	if needsRefresh(stored.Leaf) {
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
// The key is opened, never created. A cache read must leave the machine as it
// found it: on a host whose key has gone, provisioning a replacement here would
// both mint a persistent key as a side effect of a read and produce the same
// answer, since a brand new key cannot match a certificate issued against the
// old one. An absent key is reported as orphaned, which is what it means for the
// certificate holding it.
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
	current, err := provider.openKey(bindingKeyName)
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

// needsRefresh reports whether a certificate is at or past its refresh window
// and must be re-minted rather than reused.
//
// A certificate with no parsed leaf, or with a zero NotAfter, is treated as
// needing refresh rather than as healthy. A zero NotAfter is not "no expiry": it
// is a certificate whose validity could not be read, and binding a token that
// outlives the request to a certificate whose expiry is unknown is precisely the
// case this window exists to prevent. Reading it as healthy would make a
// malformed or truncated stored certificate the one entry that never expires.
func needsRefresh(leaf *x509.Certificate) bool {
	if leaf == nil || leaf.NotAfter.IsZero() {
		return true
	}
	return !leaf.NotAfter.After(now().Add(bindingCertRefreshWindow))
}

// certificateNamesIdentity checks that the certificate was issued to the
// identity the caller is about to present it as.
//
// The public key comparison in certificateMatchesKey proves only that the
// certificate carries this machine's binding key. It says nothing about which
// identity the certificate names, and the client ID sent on the token request
// is taken from the issuance response rather than from the certificate, so
// without this check a certificate for one identity could be presented while
// claiming another. IMDS puts the managed identity's client ID in the common
// name, which is where MSAL .NET reads it from too
// (MsiCertificateHelper's subject parsing).
func certificateNamesIdentity(leaf *x509.Certificate, clientID string) error {
	if leaf == nil {
		return errors.New("managedidentity: the issued certificate has no parsed leaf")
	}
	cn := strings.TrimSpace(leaf.Subject.CommonName)
	if cn == "" {
		return errors.New("managedidentity: the issued certificate has no subject common name to identify it")
	}
	// Case-folded because both sides are GUIDs and IMDS is not consistent about
	// the case it renders them in.
	if !strings.EqualFold(cn, strings.TrimSpace(clientID)) {
		return fmt.Errorf("managedidentity: the issued certificate names %q but the credential was issued for %q", cn, clientID)
	}
	return nil
}

// certificateUsableForClientMtls checks that the certificate can actually be
// presented as a client certificate, and that it is valid now.
//
// A certificate that fails any of these is refused before it is used or
// persisted. Discovering it at the handshake instead produces a TLS alert with
// no local explanation, and persisting it means every later process pays for the
// same discovery.
//
// The extension rules follow RFC 5280. An absent extended key usage places no
// restriction at all, so it is accepted; a present one has to name client
// authentication or anyExtendedKeyUsage, because a certificate explicitly
// scoped to something else is not a client credential. An absent key usage is
// likewise unrestricted, while a present one has to include digitalSignature,
// which is the bit every client-authentication handshake needs.
func certificateUsableForClientMtls(leaf *x509.Certificate) error {
	if leaf == nil {
		return errors.New("managedidentity: the issued certificate has no parsed leaf")
	}
	at := now()
	if !leaf.NotBefore.IsZero() && at.Before(leaf.NotBefore) {
		return fmt.Errorf("managedidentity: the issued certificate is not valid until %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if leaf.NotAfter.IsZero() {
		return errors.New("managedidentity: the issued certificate carries no expiry")
	}
	if !at.Before(leaf.NotAfter) {
		return fmt.Errorf("managedidentity: the issued certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if len(leaf.ExtKeyUsage) > 0 || len(leaf.UnknownExtKeyUsage) > 0 {
		ok := false
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
				ok = true
				break
			}
		}
		if !ok {
			return errors.New("managedidentity: the issued certificate's extended key usage does not allow client authentication")
		}
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("managedidentity: the issued certificate's key usage does not allow digital signature, so it cannot authenticate a TLS handshake")
	}
	return nil
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
	// A certificate that is already inside the refresh window is refused rather
	// than used once. The window is a day because Entra binds tokens with about
	// a day of life to this certificate, so binding a token to a certificate
	// that expires first hands the caller a token it cannot spend: the resource
	// rejects the handshake and nothing in the token says why. Using it for this
	// one request and not caching it would produce exactly that outcome, and
	// would also re-mint on every subsequent call against a rate-limited
	// service. Failing here names the real problem instead.
	if needsRefresh(cert.Leaf) {
		notAfter := "an unreadable time"
		if cert.Leaf != nil && !cert.Leaf.NotAfter.IsZero() {
			notAfter = cert.Leaf.NotAfter.UTC().Format(time.RFC3339)
		}
		_ = cert.Close()
		return nil, "", fmt.Errorf(
			"managedidentity: IMDS issued a binding certificate that expires at %s, which is inside the %s refresh window, so a token bound to it could outlive it",
			notAfter, bindingCertRefreshWindow)
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
	// The handle is reference counted from here on. Attestation runs the
	// uninterruptible native call on a goroutine so this caller can give up on
	// it, and that goroutine has to keep the handle alive after this function
	// has released its own reference. Every `key.Close()` below is now a
	// decrement, so nothing frees the handle while the trustlet is using it.
	holder := shareKey(&key)
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
		attestationToken, err = attestKeyGuardCached(ctx, endpoint, metadata.ClientID, key, holder)
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
	// The identity the credential was issued for has to be the identity leg 1
	// named, or the certificate is not the one this acquisition asked for.
	if err := issued.validateAgainst(metadata); err != nil {
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
	// Proving the certificate carries the binding key says nothing about which
	// identity it names, nor about whether it can be presented on a client
	// handshake at all. Both are checked before it is used or persisted.
	if err := certificateNamesIdentity(leaf, issued.ClientID); err != nil {
		_ = key.Close()
		return nil, err
	}
	if err := certificateUsableForClientMtls(leaf); err != nil {
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
