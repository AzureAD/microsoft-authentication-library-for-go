// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/storage"
)

// containsCall reports whether the fake recorded the named leg.
func containsCall(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The token endpoint is validated before a certificate is cached.
// ---------------------------------------------------------------------------

// A certificate whose issuance response named an endpoint this package will not
// dial is useless, and caching it makes it permanently useless: every later
// acquisition in the process reads the same entry from memory, and every later
// process restores it from the certificate store. The value is therefore parsed
// before either cache sees it.
func TestAnIssuedCertificateWithAMalformedEndpointIsNeverCached(t *testing.T) {
	persisted := withCleanCaches(t)
	fake := newIMDSFake(t)
	// http, not https. The token leg refuses to downgrade, so this certificate
	// can never be used.
	fake.issueEndpoint = "http://mtlsauth.plaintext.example"
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("AcquireToken succeeded with an endpoint the token leg cannot dial")
	}
	if !strings.Contains(err.Error(), "non-https") {
		t.Fatalf("AcquireToken = %v, want the endpoint to be named as the cause", err)
	}
	if _, ok := certCache.get(cacheKey(client.miType, false)); ok {
		t.Fatal("a certificate with an unusable endpoint was left in the in-memory cache")
	}
	if persisted.writes != 0 {
		t.Fatalf("persisted writes = %d, want the certificate kept out of the operating system store", persisted.writes)
	}
}

// The store is outside this process's control between runs, so a persisted
// endpoint is re-parsed on the way back in. An entry that fails is dropped from
// the store rather than adopted, otherwise every restart would restore the same
// unusable certificate and fail the same way instead of re-minting.
func TestAPersistedCertificateWithAMalformedEndpointIsDiscardedAndReminted(t *testing.T) {
	persisted := withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	// A healthy acquisition first, so the store holds a real entry.
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	alias := cacheKey(client.miType, false)
	if persisted.writes != 1 {
		t.Fatalf("persisted writes = %d, want the first acquisition to persist once", persisted.writes)
	}

	// Corrupt the stored endpoint the way another writer on the machine could,
	// then restart: drop the in-memory cache and the cached token.
	persisted.mu.Lock()
	entries := persisted.entries[alias]
	if len(entries) == 0 {
		persisted.mu.Unlock()
		t.Fatal("nothing was persisted to corrupt")
	}
	for i := range entries {
		entries[i].Endpoint = "https://mtlsauth.example\\evil.example"
	}
	persisted.mu.Unlock()
	certCache.clear()
	cacheManager = storage.New(nil)
	persisted.deletes = 0
	fake.calls = nil

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if persisted.deletes == 0 {
		t.Fatal("the unusable persisted entry was left in the store for the next restart to restore")
	}
	if !containsCall(fake.calls, "issue") {
		t.Fatalf("calls = %q, want the unusable entry replaced by a freshly issued certificate", fake.calls)
	}
}

// ---------------------------------------------------------------------------
// The process-wide gate is never held across an unbounded call.
// ---------------------------------------------------------------------------

// miTokenGate is process-wide, so whoever holds it blocks every other identity
// and every other source. A caller with no deadline talking to an endpoint that
// accepts the connection and then never answers would hold it for the life of
// the process. Each attempt is therefore bounded, which is also what MSAL .NET
// gets from HttpClient's own default.
func TestAStalledAcquisitionReleasesTheProcessWideGate(t *testing.T) {
	withCleanCaches(t)
	blocked := make(chan struct{})
	t.Cleanup(func() { close(blocked) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-blocked:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	// The metadata leg is what this acquisition will stall on.
	t.Setenv(azurePodIdentityAuthorityHostEnvVar, srv.URL)

	restore := miAttemptTimeout
	miAttemptTimeout = 150 * time.Millisecond
	t.Cleanup(func() { miAttemptTimeout = restore })

	// A plain client with no Timeout of its own, which is what an application
	// supplying its own client through WithHTTPClient usually hands over.
	client, err := New(SystemAssigned(), WithHTTPClient(&http.Client{}), WithRetryPolicyDisabled())
	if err != nil {
		t.Fatal(err)
	}
	client.keyProvider = newFakeKeyProvider()

	done := make(chan error, 1)
	go func() {
		// No deadline of its own: the bound has to come from the library.
		_, tokenErr := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
		done <- tokenErr
	}()

	select {
	case tokenErr := <-done:
		if tokenErr == nil {
			t.Fatal("AcquireToken succeeded against an endpoint that never answered")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("AcquireToken never returned, so the process-wide gate is held by an unbounded call")
	}

	// The gate has to be free again, otherwise the stall merely moved.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	release, err := acquireMITokenGate(ctx)
	if err != nil {
		t.Fatalf("acquireMITokenGate after a stalled acquisition: %v", err)
	}
	release()
}

// The library's bound is a ceiling, not a floor. A caller that asked for less
// gets less: the attempt context is derived from the caller's, so the earlier
// deadline is the one that fires.
func TestAShorterCallerDeadlineBeatsTheAttemptBound(t *testing.T) {
	withCleanCaches(t)
	blocked := make(chan struct{})
	t.Cleanup(func() { close(blocked) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-blocked:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv(azurePodIdentityAuthorityHostEnvVar, srv.URL)

	restore := miAttemptTimeout
	// Far longer than the caller's deadline, so a test that finishes quickly
	// can only have finished because the caller's deadline was honoured.
	miAttemptTimeout = 30 * time.Second
	t.Cleanup(func() { miAttemptTimeout = restore })

	client, err := New(SystemAssigned(), WithHTTPClient(&http.Client{}), WithRetryPolicyDisabled())
	if err != nil {
		t.Fatal(err)
	}
	client.keyProvider = newFakeKeyProvider()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	started := time.Now()
	if _, err := client.AcquireToken(ctx, "https://vault.azure.net", WithMtlsProofOfPossession()); err == nil {
		t.Fatal("AcquireToken succeeded against an endpoint that never answered")
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("AcquireToken took %s, so the caller's 200ms deadline was overridden by the library's bound", elapsed)
	}
}

// ---------------------------------------------------------------------------
// An indeterminate key provider does not settle the binding tier.
// ---------------------------------------------------------------------------

// A provider that failed for a local reason - VBS still starting, the KSP
// briefly unavailable - has not told us what the host can do. Caching Software
// for the life of the client would turn a passing condition into a permanent
// verdict, so the answer expires and the host is asked again.
func TestAnIndeterminateKeyProviderFailureIsNotCachedForever(t *testing.T) {
	withCleanCaches(t)
	realNow := now
	current := realNow()
	now = func() time.Time { return current }
	t.Cleanup(func() { now = realNow })

	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	provider.err = errors.New("NTE_DEVICE_NOT_READY: the platform key storage provider is starting")
	client := fake.newTestClient(t, SystemAssigned(), provider)

	got, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if got.Source != DefaultToIMDS {
		t.Fatalf("source = %q, want DefaultToIMDS: the v2 probe answered", got.Source)
	}
	if got.MaxSupportedBindingStrength != MtlsBindingStrengthSoftware {
		t.Fatalf("strength = %s, want the software floor the host proved", got.MaxSupportedBindingStrength)
	}
	if got.ErrorReason == "" {
		t.Fatal("a provider failure left no diagnostic behind")
	}

	// The condition clears. Past the retry interval the client must ask again
	// and be able to report the tier it could not measure before.
	provider.err = nil
	current = current.Add(capabilitiesRetryInterval + time.Second)
	recovered, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if recovered.MaxSupportedBindingStrength != MtlsBindingStrengthKeyGuard {
		t.Fatalf("strength = %s, want KeyGuard once the provider recovered", recovered.MaxSupportedBindingStrength)
	}
	if recovered.ErrorReason != "" {
		t.Fatalf("reason = %q, want none once a key was produced", recovered.ErrorReason)
	}
}

// A build whose platform has no key provider at all is the opposite case. That
// is chosen at compile time and cannot change while this binary runs, so it is
// answered once and not re-probed every thirty seconds.
func TestAnUnsupportedPlatformSettlesTheAnswer(t *testing.T) {
	withCleanCaches(t)
	realNow := now
	current := realNow()
	now = func() time.Time { return current }
	t.Cleanup(func() { now = realNow })

	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	provider.err = ErrMtlsNotSupportedForPlatform
	client := fake.newTestClient(t, SystemAssigned(), provider)

	got, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	// The host still speaks the protocol; this build simply cannot mint the key.
	if got.MaxSupportedBindingStrength != MtlsBindingStrengthSoftware {
		t.Fatalf("strength = %s, want the host's software floor", got.MaxSupportedBindingStrength)
	}
	if got.ErrorReason == "" {
		t.Fatal("a platform with no key provider left no diagnostic behind")
	}

	fake.calls = nil
	current = current.Add(100 * capabilitiesRetryInterval)
	if _, err = client.Capabilities(context.Background()); err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("calls = %q, want a compile-time answer settled rather than re-probed", fake.calls)
	}
}

// ---------------------------------------------------------------------------
// The retained signer outlives the operation it is signing.
// ---------------------------------------------------------------------------

// gcProbeSigner runs onSign in the middle of a signature, which is exactly when
// the wrapper must still be alive.
type gcProbeSigner struct {
	inner     crypto.Signer
	onSign    func()
	onPublic  func()
	publicHit int
}

func (g *gcProbeSigner) Public() crypto.PublicKey {
	if g.onPublic != nil {
		g.publicHit++
		g.onPublic()
	}
	return g.inner.Public()
}

func (g *gcProbeSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if g.onSign != nil {
		g.onSign()
	}
	return g.inner.Sign(r, digest, opts)
}

// retainedSigner releases the binding key from a finalizer, so the wrapper has
// to stay reachable for the whole of a delegated call. Promoting Sign from the
// embedded Signer does not do that: the call is made on the embedded field, so
// the wrapper's last use ends before the native operation starts and the
// finalizer may free the key underneath it.
//
// The wrapper is deliberately never stored in a local variable here. With an
// explicit Sign it stays alive because Sign keeps it alive; with a promoted one
// nothing does.
func TestRetainedSignerSurvivesTheSignatureItIsPerforming(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	probe := &gcProbeSigner{inner: key}
	probe.onSign = func() {
		// Give the collector every chance to notice an unreachable wrapper and
		// run its finalizer while the signature is still in progress.
		for i := 0; i < 3; i++ {
			runtime.GC()
			time.Sleep(10 * time.Millisecond)
		}
		select {
		case <-released:
			t.Error("the binding key was released while a signature was still in progress")
		default:
		}
	}

	digest := make([]byte, 32)
	if _, err := newRetainedSigner(probe, func() error {
		close(released)
		return nil
	}).Sign(rand.Reader, digest, crypto.SHA256); err != nil {
		t.Fatalf("Sign: %v", err)
	}
}

// Public has the same problem and the same fix: promoting it would end the
// wrapper's last use before the delegated call runs, so the finalizer could
// release the key while the provider is still reading the public half out of
// it. As above, the wrapper is deliberately never held in a local.
func TestRetainedSignerSurvivesPublic(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	probe := &gcProbeSigner{inner: key}
	probe.onPublic = func() {
		for i := 0; i < 3; i++ {
			runtime.GC()
			time.Sleep(10 * time.Millisecond)
		}
		select {
		case <-released:
			t.Error("the binding key was released while the public half was being read")
		default:
		}
	}

	if pub := newRetainedSigner(probe, func() error {
		close(released)
		return nil
	}).Public(); pub == nil {
		t.Fatal("Public returned nothing")
	}
	if probe.publicHit != 1 {
		t.Fatalf("the probe saw %d Public calls, want exactly one delegated call", probe.publicHit)
	}
}

// ---------------------------------------------------------------------------
// A custom mTLS factory cannot reach the cached certificate.
// ---------------------------------------------------------------------------

// A tls.Certificate passed by value still shares its DER slices and its leaf
// pointer with the cached original, so a factory that writes through either one
// would be mutating state every other acquisition in the process reads. The
// factory gets a copy of its own.
func TestACustomMtlsFactoryCannotMutateTheCachedCertificate(t *testing.T) {
	provider := newFakeKeyProvider()
	binding := testBindingCertificate(t, provider, bindingKeyName, now().Add(30*24*time.Hour))
	t.Cleanup(func() { _ = binding.Close() })
	binding.Endpoint = "https://mtlsauth.microsoft.com"

	original := append([]byte(nil), binding.TLS.Certificate[0]...)
	cachedLeaf := binding.Leaf

	var handed tls.Certificate
	c := Client{mtlsClientFactory: func(cert tls.Certificate) *http.Client {
		handed = cert
		// A factory is free to do this to a value it was given.
		cert.Certificate[0][0] ^= 0xff
		cert.Leaf.Subject.CommonName = "rewritten-by-the-factory"
		return &http.Client{}
	}}
	if _, err := c.mtlsClient(binding); err != nil {
		t.Fatalf("mtlsClient: %v", err)
	}

	if !bytes.Equal(binding.TLS.Certificate[0], original) {
		t.Fatal("the factory's write reached the cached DER")
	}
	if binding.Leaf != cachedLeaf {
		t.Fatal("the cached leaf pointer was replaced")
	}
	if binding.Leaf.Subject.CommonName == "rewritten-by-the-factory" {
		t.Fatal("the factory's write reached the cached leaf")
	}
	if handed.Leaf == cachedLeaf {
		t.Fatal("the factory was handed the cached leaf pointer")
	}
	if len(handed.Certificate) == 0 || &handed.Certificate[0][0] == &binding.TLS.Certificate[0][0] {
		t.Fatal("the factory was handed the cached DER backing array")
	}
	// The factory may keep its client, so the key behind the certificate it was
	// given has to outlive this acquisition.
	if _, ok := handed.PrivateKey.(*retainedSigner); !ok {
		t.Fatalf("the factory was handed a %T, want a signer that holds the key alive", handed.PrivateKey)
	}
}

// Isolation is the point of the copy, so a leaf that cannot be re-parsed is an
// error. Falling back to the cached leaf would hand out the very pointer the
// copy exists to withhold, and it must not retain the key on the way out.
func TestCopyingACertificateThatCannotBeReparsedFailsInsteadOfSharing(t *testing.T) {
	closed := 0
	binding := &bindingCertificate{
		TLS:  tls.Certificate{Certificate: [][]byte{[]byte("this is not a DER certificate")}},
		Leaf: &x509.Certificate{},
		refs: 1,
	}
	binding.close = func() error { closed++; return nil }

	got, err := copyBindingCertificate(binding)
	if err == nil {
		t.Fatalf("copyBindingCertificate = %+v, want an error rather than a shared leaf", got)
	}
	if got != nil {
		t.Fatal("a certificate was returned alongside the error")
	}
	binding.mu.Lock()
	refs := binding.refs
	binding.mu.Unlock()
	if refs != 1 {
		t.Fatalf("refs = %d, want the failed copy to have taken none", refs)
	}
	if closed != 0 {
		t.Fatalf("close calls = %d, want the caller's own reference untouched", closed)
	}
}

// The same failure has to surface from the factory path rather than being
// papered over with the cached certificate.
func TestMtlsClientSurfacesACopyFailure(t *testing.T) {
	binding := &bindingCertificate{
		TLS:   tls.Certificate{Certificate: [][]byte{[]byte("not DER")}},
		Leaf:  &x509.Certificate{},
		refs:  1,
		close: func() error { return nil },
	}
	called := false
	c := Client{mtlsClientFactory: func(tls.Certificate) *http.Client {
		called = true
		return &http.Client{}
	}}
	if _, err := c.mtlsClient(binding); err == nil {
		t.Fatal("mtlsClient succeeded with a certificate it could not isolate")
	}
	if called {
		t.Fatal("the factory was invoked with a certificate that could not be isolated")
	}
}
