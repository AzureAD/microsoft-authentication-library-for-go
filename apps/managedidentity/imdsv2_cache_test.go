// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// The alias is written into the certificate store, where MSAL .NET reads it. A
// prefix or a rendering of our own would file certificates under a name the
// other library does not look for, so neither could ever reuse the other's.
func TestIdentityKeyMatchesDotNetAlias(t *testing.T) {
	for _, test := range []struct {
		id   ID
		want string
	}{
		{SystemAssigned(), "system_assigned_managed_identity"},
		{UserAssignedClientID("11111111-2222-3333-4444-555555555555"), "11111111-2222-3333-4444-555555555555"},
		{UserAssignedObjectID("99999999-8888-7777-6666-555555555555"), "99999999-8888-7777-6666-555555555555"},
		{UserAssignedResourceID("/subscriptions/s/resourceGroups/g/providers/p/n"), "/subscriptions/s/resourceGroups/g/providers/p/n"},
	} {
		if got := identityKey(test.id); got != test.want {
			t.Fatalf("identityKey(%T) = %q, want %q", test.id, got, test.want)
		}
	}
}

// An attested certificate carries a guarantee a plain one does not, so a
// request that asked for attestation must never be handed one that was issued
// without it.
func TestCacheKeySeparatesAttestation(t *testing.T) {
	plain := cacheKey(SystemAssigned(), false)
	attested := cacheKey(SystemAssigned(), true)
	if plain == attested {
		t.Fatal("attested and plain certificates share a cache key")
	}
	if plain != "system_assigned_managed_identity#att=0" {
		t.Fatalf("cacheKey = %q, want the alias MSAL .NET writes", plain)
	}
	if attested != "system_assigned_managed_identity#att=1" {
		t.Fatalf("cacheKey = %q, want the alias MSAL .NET writes", attested)
	}
}

// Minting is two network round trips against a rate-limited service. A burst of
// goroutines resolving the same credential at startup must produce one
// certificate, not one per goroutine.
func TestBindingCertificateMintedOncePerIdentity(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	client := fake.newTestClient(t, SystemAssigned(), provider)

	const callers = 16
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("AcquireToken: %v", err)
		}
	}

	if issued := fake.countOf("issue"); issued != 1 {
		t.Fatalf("issued %d certificates, want 1: concurrent callers should share one mint", issued)
	}
	if provider.creates != 1 {
		t.Fatalf("created %d keys, want 1: concurrent callers should share one key", provider.creates)
	}
}

// The same single-flight property, asserted against the mint gate itself.
//
// TestBindingCertificateMintedOncePerIdentity above cannot prove the gate
// works: it goes through AcquireToken, and miTokenGate already serializes every
// managed identity acquisition process-wide, so the first caller populates the
// cache and the rest hit it no matter what the gate does. Neutering enter/leave
// entirely leaves that test green. This one calls getBindingCertificate
// directly, so the gate is the only thing standing between concurrent callers
// and one IMDS credential request each.
func TestMintGateCollapsesConcurrentIssuance(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	v := imdsV2{
		httpClient:   fake.metadataServer.Client(),
		keyProvider:  provider,
		miType:       SystemAssigned(),
		baseEndpoint: fake.metadataServer.URL,
		retryEnabled: true,
	}

	const callers = 16
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := v.getBindingCertificate(context.Background(), false)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("getBindingCertificate: %v", err)
		}
	}

	// Leg 1 runs per caller by design: it is what detects an identity change
	// underneath a cached certificate. Only issuance is gated.
	if issued := fake.countOf("issue"); issued != 1 {
		t.Fatalf("issued %d certificates, want 1: the mint gate should collapse concurrent issuance", issued)
	}
	if provider.creates != 1 {
		t.Fatalf("created %d keys, want 1", provider.creates)
	}
}

// A caller queued behind another's mint has to stay cancellable: minting makes
// two network calls, and a request whose deadline passes while it waits must
// give up rather than block for the full duration.
func TestMintGateIsCancellable(t *testing.T) {
	withCleanCaches(t)
	key := "cancellable"

	if err := certCache.enter(context.Background(), key); err != nil {
		t.Fatalf("enter: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	blocked := make(chan error, 1)
	go func() { blocked <- certCache.enter(ctx, key) }()

	// Give the second caller time to reach the gate before cancelling it, so
	// the test exercises a waiter rather than a pre-cancelled context.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-blocked:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("enter = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cancelled caller stayed blocked on the mint gate")
	}
	certCache.leave(key)
}

// A gate per identity that is never removed would grow for the life of the
// process in a host that serves many identities.
func TestMintGateDoesNotLeak(t *testing.T) {
	withCleanCaches(t)
	for i := 0; i < 4; i++ {
		key := "identity"
		if err := certCache.enter(context.Background(), key); err != nil {
			t.Fatalf("enter: %v", err)
		}
		certCache.leave(key)
	}
	certCache.mu.Lock()
	remaining := len(certCache.gates)
	certCache.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("%d gates left behind, want 0", remaining)
	}
}

// Two identities must not queue behind each other: minting is slow, and an
// unrelated identity would wait out both round trips.
func TestMintGateIsPerIdentity(t *testing.T) {
	withCleanCaches(t)
	if err := certCache.enter(context.Background(), "first"); err != nil {
		t.Fatalf("enter first: %v", err)
	}
	defer certCache.leave("first")

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := certCache.enter(ctx, "second")
		if err == nil {
			certCache.leave("second")
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a second identity was blocked by the first: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a second identity was blocked by the first")
	}
}

// Eviction happens because the service rejected the certificate. Until a new
// one is minted, nothing may serve the rejected one, or a caller retries into
// the same rejection.
func TestForceMintBlocksReadsUntilRemint(t *testing.T) {
	persisted := withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	client := fake.newTestClient(t, SystemAssigned(), provider)
	key := cacheKey(SystemAssigned(), false)

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if _, ok := certCache.get(key); !ok {
		t.Fatal("the issued certificate was not cached")
	}

	certCache.evict(key)
	if _, ok := certCache.get(key); ok {
		t.Fatal("the memory cache served a certificate the service rejected")
	}
	if _, ok := certCache.restore(key, "", provider); ok {
		t.Fatal("the store served a certificate the service rejected")
	}
	if persisted.count(key) != 0 {
		t.Fatal("the rejected certificate is still in the store")
	}

	// The next acquisition mints, which is what clears the flag; after that the
	// caches serve again.
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("AcquireToken after eviction: %v", err)
	}
	cert, ok := certCache.get(key)
	if !ok {
		t.Fatal("a freshly minted certificate was not cached, so the flag was never cleared")
	}
	_ = cert.Close()
}

// The gate serializes minting, so a certificate the caller is still using must
// not be released by a concurrent eviction. Run under -race this also proves
// the refcount is not itself a data race.
func TestConcurrentAcquireAndEvict(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	client := fake.newTestClient(t, SystemAssigned(), provider)
	key := cacheKey(SystemAssigned(), false)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
			errs <- err
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			certCache.evict(key)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("AcquireToken raced with eviction: %v", err)
		}
	}
}
