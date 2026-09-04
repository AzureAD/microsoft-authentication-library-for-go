// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto/x509"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePersistentCertCache stands in for the operating system certificate store.
//
// Tests must never reach the real store: it belongs to the user running them,
// and a test that wrote to it would leave certificates behind on the developer's
// machine and read certificates a previous run had left there.
type fakePersistentCertCache struct {
	mu      sync.Mutex
	entries map[string][]persistedCertificate
	reads   int
	writes  int
	deletes int
	// failWrite makes the store refuse to record anything, which is what a
	// machine with persistence unavailable looks like.
	failWrite bool
}

func newFakePersistentCertCache() *fakePersistentCertCache {
	return &fakePersistentCertCache{entries: map[string][]persistedCertificate{}}
}

func (f *fakePersistentCertCache) read(alias string) (*persistedCertificate, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	var newest *persistedCertificate
	for i, entry := range f.entries[alias] {
		if !entry.Leaf.NotAfter.After(now().UTC().Add(bindingCertRefreshWindow)) {
			continue
		}
		if newest == nil || entry.Leaf.NotAfter.After(newest.Leaf.NotAfter) {
			newest = &f.entries[alias][i]
		}
	}
	if newest == nil {
		return nil, false
	}
	copied := *newest
	return &copied, true
}

func (f *fakePersistentCertCache) write(alias string, cert *bindingCertificate) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	if f.failWrite {
		return
	}
	// The real store cannot record a name it cannot encode, so neither does
	// this: a test that produces such a value should see it dropped here too.
	if _, ok := encodeFriendlyName(alias, endpointBase(cert.Endpoint, cert.TenantID)); !ok {
		return
	}
	f.entries[alias] = append(f.entries[alias], persistedCertificate{
		DER:      append([]byte(nil), cert.TLS.Certificate[0]...),
		Leaf:     cert.Leaf,
		ClientID: cert.ClientID,
		TenantID: cert.TenantID,
		Endpoint: cert.Endpoint,
	})
}

func (f *fakePersistentCertCache) deleteAll(alias string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes++
	delete(f.entries, alias)
}

func (f *fakePersistentCertCache) count(alias string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.entries[alias])
}

// reset empties the store. A test that wants to prove the next acquisition
// issues a fresh certificate has to drop both caches, because either one on its
// own will happily serve the existing one.
func (f *fakePersistentCertCache) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = map[string][]persistedCertificate{}
}

// swapPersistentCache installs p as the process-wide persistent store and
// returns the one it replaced.
func swapPersistentCache(p persistentCertCache) persistentCertCache {
	certCache.mu.Lock()
	defer certCache.mu.Unlock()
	previous := certCache.persisted
	certCache.persisted = p
	return previous
}

func TestFriendlyNameRoundTrip(t *testing.T) {
	for _, test := range []struct{ alias, endpoint string }{
		{"system_assigned_managed_identity#att=0", "https://mtlsauth.microsoft.com/tenant"},
		{"11111111-2222-3333-4444-555555555555#att=1", "https://mtlsauth.microsoft.com/tenant"},
		{"/subscriptions/s/resourceGroups/g/providers/p/n#att=0", "https://mtlsauth.microsoft.com/tenant"},
	} {
		encoded, ok := encodeFriendlyName(test.alias, test.endpoint)
		if !ok {
			t.Fatalf("encodeFriendlyName(%q, %q) refused a value it should accept", test.alias, test.endpoint)
		}
		if !strings.HasPrefix(encoded, friendlyNamePrefix) {
			t.Fatalf("encoded name %q does not carry the shared prefix, so MSAL .NET would not recognize it", encoded)
		}
		alias, endpoint, ok := decodeFriendlyName(encoded)
		if !ok {
			t.Fatalf("decodeFriendlyName(%q) failed", encoded)
		}
		if alias != test.alias || endpoint != test.endpoint {
			t.Fatalf("round trip = (%q, %q), want (%q, %q)", alias, endpoint, test.alias, test.endpoint)
		}
	}
}

// A value carrying the separator would decode to something other than what was
// encoded, so it is refused rather than written and misread later.
func TestFriendlyNameRejectsUnencodableValues(t *testing.T) {
	for _, test := range []struct {
		name            string
		alias, endpoint string
	}{
		{"pipe in alias", "a|b", "https://mtlsauth.microsoft.com/tenant"},
		{"pipe in endpoint", "alias", "https://host/ten|ant"},
		{"newline", "a\nb", "https://mtlsauth.microsoft.com/tenant"},
		{"carriage return", "alias", "https://host/ten\rant"},
		{"nul", "a\x00b", "https://mtlsauth.microsoft.com/tenant"},
		{"empty alias", "", "https://mtlsauth.microsoft.com/tenant"},
		{"empty endpoint", "alias", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, ok := encodeFriendlyName(test.alias, test.endpoint); ok {
				t.Fatal("encodeFriendlyName accepted a value it cannot represent")
			}
		})
	}
}

// A name written by a newer library may carry fields this one does not know
// about. Ignoring them keeps a certificate readable across versions.
func TestFriendlyNameIgnoresUnknownFields(t *testing.T) {
	alias, endpoint, ok := decodeFriendlyName("MSAL|alias=abc|future=xyz|ep=https://host/tenant")
	if !ok {
		t.Fatal("decodeFriendlyName rejected a name carrying an unknown field")
	}
	if alias != "abc" || endpoint != "https://host/tenant" {
		t.Fatalf("decoded (%q, %q), want (\"abc\", \"https://host/tenant\")", alias, endpoint)
	}
}

func TestFriendlyNameRejectsForeignNames(t *testing.T) {
	for _, name := range []string{"", "some other certificate", "MSAL|alias=abc", "MSAL|ep=https://host/tenant", "alias=abc|ep=https://host/t"} {
		if _, _, ok := decodeFriendlyName(name); ok {
			t.Fatalf("decodeFriendlyName(%q) claimed a name that is not ours", name)
		}
	}
}

func TestEndpointBaseRoundTrip(t *testing.T) {
	for _, test := range []struct{ endpoint, tenant, want string }{
		{"https://mtlsauth.microsoft.com", "tenant", "https://mtlsauth.microsoft.com/tenant"},
		{"https://mtlsauth.microsoft.com/", "tenant", "https://mtlsauth.microsoft.com/tenant"},
		{"https://mtlsauth.microsoft.com", "/tenant/", "https://mtlsauth.microsoft.com/tenant"},
	} {
		got := endpointBase(test.endpoint, test.tenant)
		if got != test.want {
			t.Fatalf("endpointBase(%q, %q) = %q, want %q", test.endpoint, test.tenant, got, test.want)
		}
		endpoint, tenant, ok := splitEndpointBase(got)
		if !ok {
			t.Fatalf("splitEndpointBase(%q) failed", got)
		}
		if endpoint != strings.TrimRight(test.endpoint, "/") || tenant != strings.Trim(test.tenant, "/") {
			t.Fatalf("splitEndpointBase(%q) = (%q, %q)", got, endpoint, tenant)
		}
	}
}

func TestSplitEndpointBaseRejectsMalformed(t *testing.T) {
	for _, base := range []string{"", "tenant", "/tenant", "https://host/"} {
		if _, _, ok := splitEndpointBase(base); ok {
			t.Fatalf("splitEndpointBase(%q) accepted a value it cannot split", base)
		}
	}
}

// A certificate the process minted should be recoverable after a restart, which
// is the whole reason the store exists: a fleet coming back up otherwise asks
// IMDS for a fresh credential per instance and gets throttled.
func TestIMDSv2RestoresPersistedCertificate(t *testing.T) {
	persisted := withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	if persisted.count(cacheKey(SystemAssigned(), false)) != 1 {
		t.Fatal("the issued certificate was not written to the store, so a restart would re-issue it")
	}
	issued := fake.countOf("issue")

	// Only the in-memory cache is dropped: the key container and the store
	// survive a restart, so this is what the next process sees.
	certCache.clear()
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if fake.countOf("issue") != issued {
		t.Fatalf("credential requests = %d, want %d: the persisted certificate should have been reused", fake.countOf("issue"), issued)
	}
}

// The store holds the certificate, not the key. A reboot replaces the per-boot
// key, which leaves every stored certificate describing a key that no longer
// exists; serving one would produce a handshake the service rejects.
func TestIMDSv2DiscardsPersistedCertificateWhenKeyChanged(t *testing.T) {
	persisted := withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	issued := fake.countOf("issue")

	provider.rotate(t, bindingKeyName)
	certCache.clear()
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if fake.countOf("issue") != issued+1 {
		t.Fatalf("credential requests = %d, want %d: a certificate whose key was replaced must not be reused", fake.countOf("issue"), issued+1)
	}
	if persisted.count(cacheKey(SystemAssigned(), false)) != 1 {
		t.Fatal("the stale entry should have been cleared and replaced by the newly issued certificate")
	}
}

// A certificate the service rejected must not come back from the store on the
// next acquisition, or the caller retries into the same rejection forever.
func TestIMDSv2EvictionClearsPersistedCertificate(t *testing.T) {
	persisted := withCleanCaches(t)
	key := cacheKey(SystemAssigned(), false)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if persisted.count(key) != 1 {
		t.Fatal("the issued certificate was not persisted")
	}

	certCache.evict(key)
	if persisted.count(key) != 0 {
		t.Fatal("evicting a rejected certificate left it in the store, so the next acquisition would find it again")
	}
	if _, ok := certCache.get(key); ok {
		t.Fatal("the in-memory cache still served an evicted certificate")
	}
	if _, ok := certCache.restore(key, "", provider); ok {
		t.Fatal("the store was consulted for an identity marked for re-issue")
	}
}

// Persistence is an optimisation. A store that cannot record anything must cost
// a round trip, never a token.
func TestIMDSv2SucceedsWhenPersistenceFails(t *testing.T) {
	persisted := withCleanCaches(t)
	persisted.failWrite = true
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if persisted.writes == 0 {
		t.Fatal("the cache never attempted to persist the certificate")
	}
}

// An entry inside the refresh window is about to be replaced anyway, so serving
// it from the store would produce a certificate the caller immediately rejects.
func TestPersistedReadSkipsCertificatesInsideRefreshWindow(t *testing.T) {
	persisted := newFakePersistentCertCache()
	persisted.entries["alias"] = []persistedCertificate{{
		Leaf: &x509.Certificate{NotAfter: now().UTC().Add(bindingCertRefreshWindow / 2)},
	}}
	if _, ok := persisted.read("alias"); ok {
		t.Fatal("read served a certificate that is already due for replacement")
	}
	persisted.entries["alias"] = append(persisted.entries["alias"], persistedCertificate{
		Leaf: &x509.Certificate{NotAfter: now().UTC().Add(bindingCertRefreshWindow + time.Hour)},
	})
	if _, ok := persisted.read("alias"); !ok {
		t.Fatal("read skipped a certificate with life left in it")
	}
}
