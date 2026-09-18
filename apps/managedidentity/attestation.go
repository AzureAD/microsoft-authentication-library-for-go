// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ErrAttestationUnavailable reports that this host cannot produce a KeyGuard
// attestation statement, which is different from producing one and having it
// rejected. Attestation depends on AttestationClientLib.dll, a native component
// that is distributed separately and is not part of this module.
//
// This only ever reaches a caller who asked for attestation with
// WithAttestationSupport(), and it is an error rather than a downgrade: having
// asked, the caller is not quietly handed a credential that lacks it. A caller
// who did not ask never attempts attestation and never sees this.
//
// Match it with errors.Is.
var ErrAttestationUnavailable = errors.New("managedidentity: KeyGuard attestation is not available on this host")

// ErrAttestationBusy reports that too many native attestations are already in
// flight for this process to start another.
//
// It only arises after callers have abandoned attestations that the native
// library never returned from: the call cannot be interrupted, so an abandoned
// one keeps running. Refusing to start more is what stops a caller that retries
// on cancellation from accumulating stuck native calls, each holding the binding
// key handle open. Fail-closed is the right direction here, because attestation
// is opt-in and a caller who asked for it is never handed a credential without
// it.
//
// Match it with errors.Is.
var ErrAttestationBusy = errors.New("managedidentity: too many KeyGuard attestations are already in flight")

// ErrAttestationExpiresTooSoon reports that MAA returned a statement with too
// little life left to be used.
//
// A statement is only worth sending if it will still be valid when IMDS
// validates it. attestationExpiryBuffer is the margin the cache applies before
// serving one, and it is applied to a freshly produced statement for the same
// reason: minting a certificate against a statement that expires in the middle
// of the exchange produces a failure at IMDS that names nothing useful.
//
// Match it with errors.Is.
var ErrAttestationExpiresTooSoon = errors.New("managedidentity: the attestation statement expires too soon to be used")

// attestKeyGuardFn is the attestation entry point, indirected through a variable
// so a test can supply a provider on a host without KeyGuard. MSAL .NET exposes
// an equivalent hook on PopKeyAttestor for the same reason.
var attestKeyGuardFn = attestKeyGuard

// attestationExpiryBuffer is how long before its own expiry an attestation token
// stops being served from the cache, so a token is never handed out with so
// little life left that the service rejects it by the time it is read. It
// matches the buffer MSAL .NET applies to the same cache.
const attestationExpiryBuffer = 5 * time.Minute

// attestationMaxInFlight bounds how many native attestations this process will
// have running at once.
//
// One is enough for the flow: attestation is keyed by endpoint and binding key,
// the binding key is process-wide, and IMDS reports one attestation endpoint, so
// a healthy process never has more than one distinct statement to produce. The
// headroom covers a host whose reported endpoint changes mid-life. The cap
// exists because an abandoned attestation keeps running - the native call is not
// interruptible - so without it a caller in a cancel-and-retry loop would spawn
// an unbounded number of stuck native calls, each pinning a key handle.
const attestationMaxInFlight = 4

type attestationCacheEntry struct {
	token   string
	expires time.Time
}

// attestationCall is one native attestation. Every caller that wants the same
// statement waits on the same call rather than starting another, so a caller
// that gives up cannot multiply the work: the call it abandoned is the call the
// next caller joins.
type attestationCall struct {
	// done is closed once token and err are final. They are written before the
	// close and read only after it, so the channel is the whole synchronisation.
	done  chan struct{}
	token string
	err   error
}

// attestationCache holds MAA statements so that minting a second certificate for
// the same key does not pay for a second native call and MAA round trip. MSAL
// .NET caches these the same way, for the same reason.
//
// This matters because one process can hold several certificates over the same
// binding key: a system-assigned and a user-assigned identity have separate
// certificate cache entries, and re-minting after a rejected certificate issues
// another. Each of those would otherwise re-attest a key that MAA has already
// vouched for.
//
// The certificate cache's own gate does not serialize this. That gate is keyed
// by identity, while the binding key is process-wide, so two identities minting
// at once take different gates and would attest the same key concurrently.
// inflight therefore collapses concurrent attestations for one statement, which
// is what MSAL .NET's KeyedSemaphorePool in PopKeyAttestor does - except that
// joining a shared result, rather than queueing behind a lock, is also what lets
// a caller abandon the wait without abandoning the work.
var attestationCache = struct {
	mu       sync.Mutex
	entries  map[string]attestationCacheEntry
	inflight map[string]*attestationCall
}{
	entries:  map[string]attestationCacheEntry{},
	inflight: map[string]*attestationCall{},
}

// attestationCacheKey identifies a cached statement by the endpoint that issued
// it and the key it vouches for.
//
// The endpoint is part of the key because MAA instances issue their own tokens:
// a statement from one region is not valid at another.
//
// The key is identified by a fingerprint of its public half rather than by the
// name of the container holding it. A container is reused across key
// re-creation, so a name would still match after the key inside it changed, and
// the cache would serve a statement vouching for a key that no longer exists
// while the CSR carried the new one. A fingerprint changes when the key does.
//
// The client ID is deliberately absent. MAA attests the key itself and the
// client ID is forwarded as metadata, so identities sharing a binding key share
// a statement. MSAL .NET documents the same decision for the same reason.
func attestationCacheKey(endpoint string, key bindingKey) (string, error) {
	if key.Signer == nil {
		return "", errors.New("managedidentity: the binding key has no signer")
	}
	der, err := x509.MarshalPKIXPublicKey(key.Signer.Public())
	if err != nil {
		return "", fmt.Errorf("managedidentity: fingerprinting the binding key: %w", err)
	}
	sum := sha256.Sum256(der)
	normalized := strings.ToLower(strings.TrimSuffix(endpoint, "/"))
	return normalized + "|" + hex.EncodeToString(sum[:]), nil
}

// attestKeyGuardCached returns a cached statement for this key when one is still
// fresh, and otherwise attests and caches the result.
//
// The native call cannot be interrupted. It reaches into the VBS trustlet and
// then makes its own HTTPS round trip to MAA using a managed identity token it
// fetches itself, and nothing in that path takes a Go context or a deadline. It
// is therefore run on a goroutine of its own, so ctx bounds how long this caller
// waits rather than how long the work takes. That distinction is what matters
// for the process-wide token gate: an acquisition holds that gate for its whole
// duration, so a caller that could not give up here would hold it - and every
// other managed identity acquisition in the process - for as long as the native
// library stayed inside the trustlet.
//
// holder is the reference count on the binding key handle. The worker takes a
// reference before it starts and drops it when it returns, so a caller that
// walks away can close the key immediately without freeing a handle the native
// library is still using.
//
// Concurrent callers wanting the same statement join the same call rather than
// starting their own, so abandoning a wait never multiplies the native calls; a
// hard cap stops a caller that abandons repeatedly from accumulating them.
func attestKeyGuardCached(ctx context.Context, endpoint, clientID string, key bindingKey, holder *sharedKeyCloser) (string, error) {
	cacheKey, keyErr := attestationCacheKey(endpoint, key)
	// A key that cannot be fingerprinted is still attestable; it just cannot be
	// cached or collapsed with anything, since both are keyed by that
	// fingerprint. A unique key gives it the same cancellation and in-flight
	// bound without letting it share a cache entry with anything else.
	cacheable := keyErr == nil
	if !cacheable {
		cacheKey = "uncacheable|" + newCorrelationID()
	}

	if cacheable {
		if token, ok := cachedAttestation(cacheKey); ok {
			return token, nil
		}
	}

	call, mine, err := beginAttestation(cacheKey)
	if err != nil {
		return "", err
	}
	if mine {
		if !holder.retain() {
			finishAttestation(cacheKey, call, "", errors.New("managedidentity: the binding key handle was released before attestation could start"))
			return "", call.err
		}
		go runAttestation(call, cacheKey, endpoint, clientID, key, holder, cacheable)
	}

	select {
	case <-call.done:
		return call.token, call.err
	case <-ctx.Done():
		// The work continues without this caller. It is already accounted for
		// by the in-flight cap, and its result will still be cached, so the
		// next caller pays nothing for having been abandoned here.
		return "", ctx.Err()
	}
}

// beginAttestation joins the in-flight attestation for cacheKey, or registers a
// new one. The second return reports whether this caller owns the new call and
// must therefore run it.
func beginAttestation(cacheKey string) (*attestationCall, bool, error) {
	attestationCache.mu.Lock()
	defer attestationCache.mu.Unlock()
	if call, ok := attestationCache.inflight[cacheKey]; ok {
		return call, false, nil
	}
	if len(attestationCache.inflight) >= attestationMaxInFlight {
		return nil, false, fmt.Errorf("%w: %d are running and none has returned",
			ErrAttestationBusy, len(attestationCache.inflight))
	}
	call := &attestationCall{done: make(chan struct{})}
	attestationCache.inflight[cacheKey] = call
	return call, true, nil
}

// finishAttestation publishes the result of a call and retires it, so the next
// caller starts a fresh one rather than joining a completed one.
func finishAttestation(cacheKey string, call *attestationCall, token string, err error) {
	attestationCache.mu.Lock()
	if attestationCache.inflight[cacheKey] == call {
		delete(attestationCache.inflight, cacheKey)
	}
	attestationCache.mu.Unlock()
	call.token, call.err = token, err
	close(call.done)
}

// runAttestation performs the native call on its own goroutine and publishes the
// result to everybody waiting on it.
func runAttestation(call *attestationCall, cacheKey, endpoint, clientID string, key bindingKey, holder *sharedKeyCloser, cacheable bool) {
	// The handle stays alive for exactly as long as the native library can
	// still touch it, whatever the caller that started this has done since.
	defer func() { _ = holder.release() }()

	token, err := attestKeyGuardFn(endpoint, clientID, key)
	if err != nil {
		finishAttestation(cacheKey, call, "", err)
		return
	}

	// A statement whose lifetime cannot be read is used but not stored: caching
	// it would mean guessing when to stop trusting it. MSAL .NET arrives at the
	// same behaviour by treating a missing expiry as already expired.
	//
	// A statement whose lifetime is readable but already inside the buffer is
	// refused outright rather than used once. The cache would not serve it to
	// anybody, so using it here would make this one caller the only one to trust
	// a statement every other reader rejects, and it is about to be sent to IMDS
	// as the evidence behind a certificate.
	if expires, ok := attestationTokenExpiry(token); ok {
		if !expires.After(now().Add(attestationExpiryBuffer)) {
			finishAttestation(cacheKey, call, "", fmt.Errorf("%w: it expires at %s, within the %s buffer",
				ErrAttestationExpiresTooSoon, expires.UTC().Format(time.RFC3339), attestationExpiryBuffer))
			return
		}
		if cacheable {
			attestationCache.mu.Lock()
			attestationCache.entries[cacheKey] = attestationCacheEntry{token: token, expires: expires}
			attestationCache.mu.Unlock()
		}
	}
	finishAttestation(cacheKey, call, token, nil)
}

// cachedAttestation returns a statement that is still comfortably in date,
// dropping one that is not so a later caller does not re-examine it.
func cachedAttestation(cacheKey string) (string, bool) {
	attestationCache.mu.Lock()
	defer attestationCache.mu.Unlock()
	entry, ok := attestationCache.entries[cacheKey]
	if !ok {
		return "", false
	}
	if entry.expires.After(now().Add(attestationExpiryBuffer)) {
		return entry.token, true
	}
	delete(attestationCache.entries, cacheKey)
	return "", false
}

// attestationTokenExpiry reads the exp claim of a JWT. It reports whether one
// was found, so a token without a readable lifetime is distinguishable from one
// that expired at the zero time.
func attestationTokenExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp *int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == nil {
		return time.Time{}, false
	}
	return time.Unix(*claims.Exp, 0), true
}

// clearAttestationCache drops every cached statement. Tests use it to isolate
// themselves from one another, since the cache is process-wide.
//
// In-flight calls are deliberately left alone: they own a reference on a key
// handle and cannot be interrupted, so forgetting them would let a later test
// start a call the cap was meant to refuse.
func clearAttestationCache() {
	attestationCache.mu.Lock()
	defer attestationCache.mu.Unlock()
	attestationCache.entries = map[string]attestationCacheEntry{}
}
