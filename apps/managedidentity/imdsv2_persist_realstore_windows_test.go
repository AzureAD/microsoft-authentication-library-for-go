// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build windows

package managedidentity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// These tests drive the real CurrentUser\My certificate store through crypt32,
// which is the one part of the persistent cache that a fake cannot exercise.
// They are off by default because they mutate a store that belongs to the user
// running them; set MSAL_TEST_REAL_CERT_STORE=1 to opt in.
//
// Every entry they create is scoped to an alias generated for the run and
// removed again in cleanup, so a run cannot disturb a certificate that belongs
// to anything else.
const realStoreEnvVar = "MSAL_TEST_REAL_CERT_STORE"

func requireRealStore(t *testing.T) windowsPersistentCertCache {
	t.Helper()
	if os.Getenv(realStoreEnvVar) != "1" {
		t.Skipf("set %s=1 to run tests against the real certificate store", realStoreEnvVar)
	}
	return windowsPersistentCertCache{}
}

// uniqueAlias returns an alias no other caller will be using.
func uniqueAlias(t *testing.T) string {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("rand: %v", err)
	}
	return fmt.Sprintf("msal-go-selftest-%d-%d", time.Now().UnixNano(), n.Int64())
}

// scopedAlias hands back an alias that is emptied from the store afterwards,
// whether or not the test passes.
func scopedAlias(t *testing.T, store windowsPersistentCertCache) string {
	t.Helper()
	alias := uniqueAlias(t)
	t.Cleanup(func() {
		store.deleteAll(alias)
		if got, ok := store.read(alias); ok {
			t.Errorf("cleanup left %s behind in the store (subject %s)", alias, got.Leaf.Subject.CommonName)
		}
	})
	return alias
}

// makeBindingCert builds a self-signed certificate shaped like one IMDS issues:
// the client ID is the common name, which is where the cache reads it back from.
func makeBindingCert(t *testing.T, clientID, tenantID, endpoint string, notAfter time.Time) *bindingCertificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: clientID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return &bindingCertificate{
		TLS:      tls.Certificate{Certificate: [][]byte{der}, Leaf: leaf},
		Leaf:     leaf,
		ClientID: clientID,
		TenantID: tenantID,
		Endpoint: endpoint,
	}
}

// countRealStore reports how many certificates the store holds for alias.
//
// The read path only ever returns the newest entry, so it cannot distinguish a
// write that was correctly skipped from one that added a redundant entry.
// Counting is what makes that observable.
func countRealStore(t *testing.T, alias string) int {
	t.Helper()
	store, err := openMyStore(true)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = windows.CertCloseStore(store, 0) }()

	contexts := snapshotStore(store)
	defer freeContexts(contexts)

	n := 0
	for _, ctx := range contexts {
		name, _, ok := decodeFriendlyName(friendlyName(ctx))
		if ok && name == alias && usesBindingKeyContainer(ctx) {
			n++
		}
	}
	return n
}

// TestRealStoreRoundTrip is the core proof: a certificate written through
// crypt32 comes back with every field the acquisition path needs, recovered
// from the store rather than from memory.
func TestRealStoreRoundTrip(t *testing.T) {
	store := requireRealStore(t)
	alias := scopedAlias(t, store)

	const (
		clientID = "8c8a1b0a-4d40-4d9e-9a4f-1f2a3b4c5d6e"
		tenantID = "72f988bf-86f1-41af-91ab-2d7cd011db47"
		endpoint = "https://169.254.169.254/metadata/identity/oauth2/token"
	)
	want := makeBindingCert(t, clientID, tenantID, endpoint, time.Now().Add(30*24*time.Hour))

	store.write(alias, want)

	got, ok := store.read(alias)
	if !ok {
		t.Fatal("read found nothing after write; the certificate did not reach the store")
	}
	if got.ClientID != clientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, clientID)
	}
	if got.TenantID != tenantID {
		t.Errorf("TenantID = %q, want %q", got.TenantID, tenantID)
	}
	if got.Endpoint != endpoint {
		t.Errorf("Endpoint = %q, want %q", got.Endpoint, endpoint)
	}
	if !got.Leaf.Equal(want.Leaf) {
		t.Error("the certificate read back is not the one written")
	}
	if string(got.DER) != string(want.TLS.Certificate[0]) {
		t.Error("DER read back does not match the DER written")
	}
}

// TestRealStoreIsolatesAliases proves the friendly name really scopes a lookup:
// writing one identity must not make it visible to another.
func TestRealStoreIsolatesAliases(t *testing.T) {
	store := requireRealStore(t)
	mine := scopedAlias(t, store)
	other := scopedAlias(t, store)

	expiry := time.Now().Add(30 * 24 * time.Hour)
	store.write(mine, makeBindingCert(t, "11111111-1111-1111-1111-111111111111", "tenant-a", "https://a.example", expiry))

	if _, ok := store.read(other); ok {
		t.Fatal("a certificate written for one alias was visible to another")
	}

	store.write(other, makeBindingCert(t, "22222222-2222-2222-2222-222222222222", "tenant-b", "https://b.example", expiry))

	a, ok := store.read(mine)
	if !ok {
		t.Fatal("the first alias lost its certificate when a second was written")
	}
	b, ok := store.read(other)
	if !ok {
		t.Fatal("the second alias has no certificate")
	}
	if a.ClientID == b.ClientID {
		t.Fatalf("both aliases returned the same certificate (%s)", a.ClientID)
	}
	if a.TenantID != "tenant-a" || b.TenantID != "tenant-b" {
		t.Errorf("tenants crossed over: %q and %q", a.TenantID, b.TenantID)
	}
}

// TestRealStoreSkipsNearExpiry proves the refresh window is applied on the read
// path, so a restart cannot adopt a certificate that is about to die.
func TestRealStoreSkipsNearExpiry(t *testing.T) {
	store := requireRealStore(t)
	alias := scopedAlias(t, store)

	// Inside bindingCertRefreshWindow, so not worth restoring.
	store.write(alias, makeBindingCert(t, "33333333-3333-3333-3333-333333333333", "tenant", "https://c.example",
		time.Now().Add(bindingCertRefreshWindow/2)))

	if got, ok := store.read(alias); ok {
		t.Fatalf("read returned a certificate expiring at %s, inside the %s refresh window",
			got.Leaf.NotAfter, bindingCertRefreshWindow)
	}
}

// TestRealStoreKeepsNewest proves that when several certificates exist for one
// identity the read picks the one with the most life left, and that a write
// does not displace a better entry that is already there.
func TestRealStoreKeepsNewest(t *testing.T) {
	store := requireRealStore(t)
	alias := scopedAlias(t, store)

	const clientID = "44444444-4444-4444-4444-444444444444"
	sooner := time.Now().Add(10 * 24 * time.Hour)
	later := time.Now().Add(40 * 24 * time.Hour)

	store.write(alias, makeBindingCert(t, clientID, "tenant", "https://d.example", sooner))
	newest := makeBindingCert(t, clientID, "tenant", "https://d.example", later)
	store.write(alias, newest)

	got, ok := store.read(alias)
	if !ok {
		t.Fatal("no certificate for the alias")
	}
	if !got.Leaf.Equal(newest.Leaf) {
		t.Errorf("read returned the certificate expiring %s, want the one expiring %s",
			got.Leaf.NotAfter, newest.Leaf.NotAfter)
	}
}

// TestRealStoreDoesNotDisplaceNewer proves the write path skips when the store
// already holds a certificate at least as good.
//
// This is asserted by counting entries, not by reading: read always returns the
// newest entry, so it would report success even if the redundant certificate
// had been added.
func TestRealStoreDoesNotDisplaceNewer(t *testing.T) {
	store := requireRealStore(t)
	alias := scopedAlias(t, store)

	const clientID = "88888888-8888-8888-8888-888888888888"
	later := makeBindingCert(t, clientID, "tenant", "https://g.example", time.Now().Add(40*24*time.Hour))
	store.write(alias, later)

	if n := countRealStore(t, alias); n != 1 {
		t.Fatalf("after the first write the store holds %d certificates, want 1", n)
	}

	// A concurrent process could have issued this one before the better entry
	// landed. Storing it would leave a worse certificate behind for no gain.
	store.write(alias, makeBindingCert(t, clientID, "tenant", "https://g.example", time.Now().Add(10*24*time.Hour)))

	if n := countRealStore(t, alias); n != 1 {
		t.Errorf("writing an older certificate added an entry: store holds %d, want 1", n)
	}
	got, ok := store.read(alias)
	if !ok {
		t.Fatal("the certificate disappeared")
	}
	if !got.Leaf.Equal(later.Leaf) {
		t.Error("the newer certificate is no longer the one served")
	}
}

// TestRealStoreDeleteAll proves eviction really reaches the operating system,
// which is what makes forceMint safe across a restart.
func TestRealStoreDeleteAll(t *testing.T) {
	store := requireRealStore(t)
	victim := scopedAlias(t, store)
	bystander := scopedAlias(t, store)

	expiry := time.Now().Add(30 * 24 * time.Hour)
	store.write(victim, makeBindingCert(t, "55555555-5555-5555-5555-555555555555", "tenant", "https://e.example", expiry))
	store.write(victim, makeBindingCert(t, "55555555-5555-5555-5555-555555555555", "tenant", "https://e.example", expiry.Add(time.Hour)))
	store.write(bystander, makeBindingCert(t, "66666666-6666-6666-6666-666666666666", "tenant", "https://f.example", expiry))

	if _, ok := store.read(victim); !ok {
		t.Fatal("setup failed: nothing stored for the victim alias")
	}

	store.deleteAll(victim)

	if got, ok := store.read(victim); ok {
		t.Errorf("deleteAll left a certificate behind (expires %s)", got.Leaf.NotAfter)
	}
	if _, ok := store.read(bystander); !ok {
		t.Error("deleteAll removed a certificate belonging to a different alias")
	}
}

// TestRealStoreEncodesEndpointFaithfully proves the friendly-name codec
// survives a real round trip through the store, including an endpoint that
// contains slashes. That is the field MSAL .NET has to be able to decode.
func TestRealStoreEncodesEndpointFaithfully(t *testing.T) {
	store := requireRealStore(t)
	alias := scopedAlias(t, store)

	const (
		tenantID = "72f988bf-86f1-41af-91ab-2d7cd011db47"
		endpoint = "https://169.254.169.254/metadata/identity/oauth2/token"
	)
	store.write(alias, makeBindingCert(t, "77777777-7777-7777-7777-777777777777", tenantID, endpoint,
		time.Now().Add(30*24*time.Hour)))

	got, ok := store.read(alias)
	if !ok {
		t.Fatal("nothing stored")
	}
	if got.Endpoint != endpoint {
		t.Errorf("Endpoint = %q, want %q; the codec lost a path segment", got.Endpoint, endpoint)
	}
	if got.TenantID != tenantID {
		t.Errorf("TenantID = %q, want %q", got.TenantID, tenantID)
	}
}
