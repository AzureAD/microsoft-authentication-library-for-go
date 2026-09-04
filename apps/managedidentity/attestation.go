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

// attestKeyGuardFn is the attestation entry point, indirected through a variable
// so a test can supply a provider on a host without KeyGuard. MSAL .NET exposes
// an equivalent hook on PopKeyAttestor for the same reason.
var attestKeyGuardFn = attestKeyGuard

// attestationExpiryBuffer is how long before its own expiry an attestation token
// stops being served from the cache, so a token is never handed out with so
// little life left that the service rejects it by the time it is read. It
// matches the buffer MSAL .NET applies to the same cache.
const attestationExpiryBuffer = 5 * time.Minute

type attestationCacheEntry struct {
	token   string
	expires time.Time
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
// at once take different gates and attest the same key concurrently. gates
// therefore holds a second set keyed by the statement rather than the identity,
// which is what MSAL .NET's KeyedSemaphorePool in PopKeyAttestor does.
var attestationCache = struct {
	mu      sync.Mutex
	entries map[string]attestationCacheEntry
	gates   map[string]*mintGate
}{
	entries: map[string]attestationCacheEntry{},
	gates:   map[string]*mintGate{},
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
// Concurrent misses for the same key are collapsed into one attestation. The
// native call and the MAA round trip behind it are expensive and MAA is
// rate-limited, so letting every caller through would multiply both for no gain.
func attestKeyGuardCached(ctx context.Context, endpoint, clientID string, key bindingKey) (string, error) {
	cacheKey, keyErr := attestationCacheKey(endpoint, key)
	// A key that cannot be fingerprinted is still attestable; it just cannot be
	// cached or collapsed with anything, since both are keyed by that
	// fingerprint. The flow continues uncoordinated rather than failing.
	if keyErr != nil {
		return attestKeyGuardFn(endpoint, clientID, key)
	}

	if token, ok := cachedAttestation(cacheKey); ok {
		return token, nil
	}

	if err := enterAttestation(ctx, cacheKey); err != nil {
		return "", err
	}
	defer leaveAttestation(cacheKey)

	// Whoever held the gate may have cached a statement while this caller
	// waited, which is the point of having waited.
	if token, ok := cachedAttestation(cacheKey); ok {
		return token, nil
	}

	token, err := attestKeyGuardFn(endpoint, clientID, key)
	if err != nil {
		return "", err
	}

	// A statement whose lifetime cannot be read is used but not stored: caching
	// it would mean guessing when to stop trusting it. MSAL .NET arrives at the
	// same behaviour by treating a missing expiry as already expired.
	if expires, ok := attestationTokenExpiry(token); ok {
		attestationCache.mu.Lock()
		attestationCache.entries[cacheKey] = attestationCacheEntry{token: token, expires: expires}
		attestationCache.mu.Unlock()
	}
	return token, nil
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

// enterAttestation blocks until this caller is the only one attesting cacheKey.
func enterAttestation(ctx context.Context, cacheKey string) error {
	attestationCache.mu.Lock()
	gate, ok := attestationCache.gates[cacheKey]
	if !ok {
		gate = &mintGate{ch: make(chan struct{}, 1)}
		attestationCache.gates[cacheKey] = gate
	}
	gate.waiters++
	attestationCache.mu.Unlock()

	select {
	case gate.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		releaseAttestationWaiter(cacheKey)
		return ctx.Err()
	}
}

// leaveAttestation releases the gate taken by enterAttestation.
func leaveAttestation(cacheKey string) {
	attestationCache.mu.Lock()
	gate, ok := attestationCache.gates[cacheKey]
	attestationCache.mu.Unlock()
	if !ok {
		return
	}
	<-gate.ch
	releaseAttestationWaiter(cacheKey)
}

func releaseAttestationWaiter(cacheKey string) {
	attestationCache.mu.Lock()
	defer attestationCache.mu.Unlock()
	if gate, ok := attestationCache.gates[cacheKey]; ok {
		gate.waiters--
		if gate.waiters <= 0 {
			delete(attestationCache.gates, cacheKey)
		}
	}
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
func clearAttestationCache() {
	attestationCache.mu.Lock()
	defer attestationCache.mu.Unlock()
	attestationCache.entries = map[string]attestationCacheEntry{}
}
