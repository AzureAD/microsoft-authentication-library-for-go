// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package storage

import (
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

// schemedAccessToken builds a non-bearer access token that carries an authentication scheme key ID,
// which is the only shape affected by the duplicate-key eviction.
func schemedAccessToken(tokenType, keyID, secret string) AccessToken {
	now := time.Now()
	return NewAccessToken(
		"home-account", "login.microsoftonline.com", "contoso.onmicrosoft.com", "client-id",
		now, now, now.Add(time.Hour), now.Add(2*time.Hour),
		"scope-a scope-b", secret, tokenType, keyID,
	)
}

// TestWriteAccessTokenEvictsSupersededKey covers the duplicate an upgrade leaves behind. Before the
// authentication scheme's key ID became part of AccessToken.Key(), a non-bearer token was written
// one component short. readAccessToken filters on struct fields and never on the key, so after the
// upgrade both entries match the same request and Go's randomized map iteration decides which one is
// served; the stale one is never overwritten, so it lingers forever.
//
// This is the pre-existing WithAuthenticationScheme PoP/SHR path, not only mtls_pop, which is why
// the case below uses "pop".
func TestWriteAccessTokenEvictsSupersededKey(t *testing.T) {
	for _, tokenType := range []string{"pop", authority.AccessTokenTypeMtlsPoP} {
		t.Run(tokenType, func(t *testing.T) {
			fresh := schemedAccessToken(tokenType, "key-id-1", "fresh")
			legacy := fresh
			legacy.Secret = "legacy"

			legacyKey := legacy.keyWithoutAuthnSchemeKeyID()
			if legacyKey == fresh.Key() {
				t.Fatal("the pre-key-ID key is identical to the current key; this test would prove nothing")
			}

			m := &Manager{contract: NewContract()}
			m.contract.AccessTokens[legacyKey] = legacy

			if err := m.writeAccessToken(fresh); err != nil {
				t.Fatal(err)
			}
			if got := len(m.contract.AccessTokens); got != 1 {
				t.Fatalf("cache holds %d access tokens after the upgrade write, want 1", got)
			}
			at, ok := m.contract.AccessTokens[fresh.Key()]
			if !ok {
				t.Fatal("the token was not written under the current key")
			}
			if at.Secret != "fresh" {
				t.Errorf("the surviving entry has secret %q, want the freshly written one", at.Secret)
			}
		})
	}
}

// TestWriteAccessTokenKeepsUnrelatedEntries pins the eviction's blast radius. Only the entry that is
// this exact token under the older key shape may be removed.
func TestWriteAccessTokenKeepsUnrelatedEntries(t *testing.T) {
	fresh := schemedAccessToken(authority.AccessTokenTypeMtlsPoP, "key-id-1", "fresh")

	// Same everything except the key ID: a token bound to a different certificate. It has its own
	// current-shaped key and must survive.
	otherCert := schemedAccessToken(authority.AccessTokenTypeMtlsPoP, "key-id-2", "other-cert")

	// A non-bearer token with no key ID at all. Its current key is byte-identical to the older
	// shape of fresh's key, so a blind delete-by-computed-key would evict it. readAccessToken would
	// never return it for a request carrying key-id-1, so it is a distinct, still-reachable entry.
	noKeyID := schemedAccessToken(authority.AccessTokenTypeMtlsPoP, "", "no-key-id")
	if noKeyID.Key() != fresh.keyWithoutAuthnSchemeKeyID() {
		t.Fatalf("test setup is wrong: %q != %q", noKeyID.Key(), fresh.keyWithoutAuthnSchemeKeyID())
	}

	// A bearer token for the same identity, which keys off a different shape entirely.
	bearer := schemedAccessToken(authority.AccessTokenTypeBearer, "", "bearer")

	m := &Manager{contract: NewContract()}
	for _, at := range []AccessToken{otherCert, noKeyID, bearer} {
		if err := m.writeAccessToken(at); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.writeAccessToken(fresh); err != nil {
		t.Fatal(err)
	}

	for _, want := range []AccessToken{otherCert, noKeyID, bearer, fresh} {
		got, ok := m.contract.AccessTokens[want.Key()]
		if !ok {
			t.Fatalf("entry %q was evicted", want.Key())
		}
		if got.Secret != want.Secret {
			t.Errorf("entry %q holds secret %q, want %q", want.Key(), got.Secret, want.Secret)
		}
	}
	if got := len(m.contract.AccessTokens); got != 4 {
		t.Errorf("cache holds %d access tokens, want 4", got)
	}
}

// TestWriteBearerAccessTokenIsUntouched pins that the hot path is unchanged: a bearer token has no
// older key shape, so the write must remain a plain overwrite of its own key and must never remove
// anything else.
func TestWriteBearerAccessTokenIsUntouched(t *testing.T) {
	first := schemedAccessToken(authority.AccessTokenTypeBearer, "", "first")
	second := first
	second.Secret = "second"

	m := &Manager{contract: NewContract()}
	if err := m.writeAccessToken(first); err != nil {
		t.Fatal(err)
	}
	if err := m.writeAccessToken(second); err != nil {
		t.Fatal(err)
	}
	if got := len(m.contract.AccessTokens); got != 1 {
		t.Fatalf("cache holds %d access tokens, want 1", got)
	}
	if got := m.contract.AccessTokens[second.Key()]; got.Secret != "second" {
		t.Errorf("bearer entry holds secret %q, want the second write", got.Secret)
	}
	// A bearer token's key never carries the key ID, so the two key forms coincide and the eviction
	// helper must bail out before touching the map at all.
	if first.Key() != first.keyWithoutAuthnSchemeKeyID() {
		t.Error("a bearer token's key changed shape; the guard in evictSupersededAccessToken relies on it not doing so")
	}
}

// TestPartitionedWriteAccessTokenEvictsSupersededKey covers the same duplicate in the OBO cache,
// whose readAccessToken also matches on struct fields rather than on the key.
func TestPartitionedWriteAccessTokenEvictsSupersededKey(t *testing.T) {
	const partition = "partition-key"

	fresh := schemedAccessToken(authority.AccessTokenTypeMtlsPoP, "key-id-1", "fresh")
	legacy := fresh
	legacy.Secret = "legacy"

	m := &PartitionedManager{contract: NewInMemoryContract()}
	m.contract.AccessTokensPartition[partition] = map[string]AccessToken{
		legacy.keyWithoutAuthnSchemeKeyID(): legacy,
	}
	// An entry in a different partition is out of scope and must survive.
	other := fresh
	other.Secret = "other-partition"
	m.contract.AccessTokensPartition["elsewhere"] = map[string]AccessToken{
		other.keyWithoutAuthnSchemeKeyID(): other,
	}

	if err := m.writeAccessToken(fresh, partition); err != nil {
		t.Fatal(err)
	}
	if got := len(m.contract.AccessTokensPartition[partition]); got != 1 {
		t.Fatalf("partition holds %d access tokens after the upgrade write, want 1", got)
	}
	if got := m.contract.AccessTokensPartition[partition][fresh.Key()]; got.Secret != "fresh" {
		t.Errorf("the surviving entry has secret %q, want the freshly written one", got.Secret)
	}
	if got := len(m.contract.AccessTokensPartition["elsewhere"]); got != 1 {
		t.Errorf("another partition lost %d entries", 1-got)
	}
}
