// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Reading the cache must not change the machine.
// ---------------------------------------------------------------------------

// A cache read asks whether the key a certificate was issued against is still
// there. On a host that has no key the answer is no, and provisioning one to
// discover that would create a persistent CNG container - shared with MSAL .NET
// and surviving restarts - as a side effect of a read, without changing the
// answer at all.
func TestCacheReadsNeverProvisionAKey(t *testing.T) {
	provider := newFakeKeyProvider()
	cert := testBindingCertificate(t, provider, "an-unrelated-container", time.Now().Add(30*24*time.Hour))

	if !isOrphaned(cert, provider) {
		t.Fatal("a certificate whose key does not exist should read as orphaned")
	}
	if provider.creates != 1 {
		t.Fatalf("the orphan check created %d keys, want none beyond the fixture's", provider.creates-1)
	}
	if provider.opensWithoutKey == 0 {
		t.Fatal("the orphan check did not go through the open-only path")
	}
}

// restore reopens the key a persisted certificate was issued against. It must
// not create one either: a freshly created key cannot match a certificate
// issued against the old one, so the read would provision a key and still fail.
func TestRestoreNeverProvisionsAKey(t *testing.T) {
	withCleanCaches(t)
	provider := newFakeKeyProvider()
	cert := testBindingCertificate(t, provider, "an-unrelated-container", time.Now().Add(30*24*time.Hour))
	before := provider.creates

	// The persisted cache is empty, so this returns immediately; the point is
	// that nothing on the way there reached getOrCreateKey.
	if _, ok := certCache.restore("alias", cert.ClientID, cert.TenantID, provider); ok {
		t.Fatal("restore found a certificate in an empty store")
	}
	if provider.creates != before {
		t.Fatalf("restore created %d keys, want 0", provider.creates-before)
	}
}

// ---------------------------------------------------------------------------
// Attestation: cancellation, bounding, and freshness.
// ---------------------------------------------------------------------------

// A caller whose context ends must stop waiting for the native attestation,
// which cannot be interrupted, and must not block on releasing the binding key
// while that call is still using the handle. Holding either would hold the
// process-wide token gate for as long as the native library stayed inside the
// trustlet, stalling every other managed identity acquisition in the process.
func TestAttestationCancellationReleasesTheCallerAndTheKey(t *testing.T) {
	clearAttestationCache()
	t.Cleanup(clearAttestationCache)

	signer, err := rsa.GenerateKey(rand.Reader, csrKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	var closed bool
	var closeMu sync.Mutex
	key := bindingKey{Signer: signer, Type: keyTypeKeyGuard, Close: func() error {
		closeMu.Lock()
		defer closeMu.Unlock()
		closed = true
		return nil
	}}
	holder := shareKey(&key)

	stuck := make(chan struct{})
	// The worker outlives the caller by design, so the fixture must not be
	// restored until it has actually returned: unhooking attestKeyGuardFn while
	// an abandoned worker is still inside it is a data race on the hook itself.
	var running sync.WaitGroup
	running.Add(1)
	original := attestKeyGuardFn
	attestKeyGuardFn = func(string, string, bindingKey) (string, error) {
		defer running.Done()
		<-stuck
		return "", errors.New("released")
	}
	t.Cleanup(func() {
		close(stuck)
		running.Wait()
		attestKeyGuardFn = original
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := attestKeyGuardCached(ctx, "https://attestation.example", "client", key, holder)
		// The caller releases its own reference exactly as
		// issueBindingCertificate does on the error path.
		_ = key.Close()
		done <- err
	}()

	// Give the worker time to enter the native call before cancelling, so the
	// test exercises "abandon work in progress" rather than "never started".
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("AcquireToken returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cancelled caller was still waiting on the native attestation")
	}

	// The abandoned call still holds a reference, so the handle must not have
	// been freed underneath it.
	closeMu.Lock()
	stillOpen := !closed
	closeMu.Unlock()
	if !stillOpen {
		t.Fatal("the binding key was released while the native call was still using it")
	}
}

// The claim the worker design rests on is about the process-wide token gate:
// an acquisition holds it for its whole duration, so a caller that could not
// abandon an uninterruptible native attestation would hold that gate - and
// every other managed identity acquisition in the process - for as long as the
// native library stayed inside the trustlet. This drives the whole acquisition
// rather than the attestation helper, so the gate is the thing observed.
func TestCancelledAttestationReleasesTheProcessWideTokenGate(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)

	stuck := make(chan struct{})
	var running sync.WaitGroup
	running.Add(1)
	original := attestKeyGuardFn
	attestKeyGuardFn = func(string, string, bindingKey) (string, error) {
		defer running.Done()
		<-stuck
		return "", errors.New("released")
	}
	t.Cleanup(func() {
		close(stuck)
		running.Wait()
		attestKeyGuardFn = original
	})

	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := client.AcquireToken(ctx, "https://vault.azure.net",
			WithMtlsProofOfPossession(), WithAttestationSupport())
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("AcquireToken succeeded while the attestation was still stuck")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AcquireToken did not return after its context expired")
	}

	// The gate is the point: it must be free even though the native call the
	// cancelled acquisition started is still running.
	release, ok := tryAcquireMITokenGate()
	if !ok {
		t.Fatal("the process-wide token gate was still held after a cancelled acquisition returned")
	}
	release()

	// And an unrelated acquisition really can proceed.
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithRequestOverMtls()); err != nil {
		t.Fatalf("a later acquisition failed behind a stuck attestation: %v", err)
	}
}

// The native call cannot be interrupted, so an abandoned one keeps running. A
// caller that cancels and retries must therefore not be able to accumulate
// stuck native calls, each pinning a key handle.
func TestAttestationInFlightCallsAreBounded(t *testing.T) {
	clearAttestationCache()
	t.Cleanup(clearAttestationCache)

	signer, err := rsa.GenerateKey(rand.Reader, csrKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	key := bindingKey{Signer: signer, Type: keyTypeKeyGuard, Close: func() error { return nil }}
	holder := shareKey(&key)
	t.Cleanup(func() { _ = holder.release() })

	stuck := make(chan struct{})
	// Every worker started below is abandoned by its caller and keeps running,
	// which is the condition the cap exists for. The hook must therefore stay
	// installed until all of them have returned, or restoring it would race
	// with the reads still in flight.
	var running sync.WaitGroup
	running.Add(attestationMaxInFlight)
	original := attestKeyGuardFn
	attestKeyGuardFn = func(string, string, bindingKey) (string, error) {
		defer running.Done()
		<-stuck
		return "", errors.New("released")
	}
	t.Cleanup(func() {
		close(stuck)
		running.Wait()
		attestKeyGuardFn = original
	})

	// Each distinct endpoint is a distinct statement, so each starts its own
	// call. Filling the cap this way is what a caller varying the endpoint - or
	// simply retrying after cancellation - would do.
	for i := 0; i < attestationMaxInFlight; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		_, err := attestKeyGuardCached(ctx, fmt.Sprintf("https://attestation%d.example", i), "client", key, holder)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("call %d returned %v, want the caller to give up", i, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = attestKeyGuardCached(ctx, "https://attestation-overflow.example", "client", key, holder)
	if !errors.Is(err, ErrAttestationBusy) {
		t.Fatalf("the call past the cap returned %v, want ErrAttestationBusy", err)
	}
}

// A statement is only worth sending if it will still be valid when IMDS reads
// it. The cache refuses to serve one inside the expiry buffer, so using a fresh
// one that is already inside it would make this caller the only party trusting
// a statement every other reader rejects.
func TestAttestationRejectsAFreshStatementThatExpiresTooSoon(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	// Two minutes of life, well inside the five-minute buffer.
	withCountedAttestation(t, func() string { return stubAttestationJWT(t, now().Add(2*time.Minute)) })

	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())
	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithAttestationSupport())
	if !errors.Is(err, ErrAttestationExpiresTooSoon) {
		t.Fatalf("AcquireToken = %v, want ErrAttestationExpiresTooSoon", err)
	}
	if fake.countOf("token") != 0 {
		t.Fatal("a token was requested with a statement that was about to expire")
	}
}

// ---------------------------------------------------------------------------
// What the service says has to be checked before it is used.
// ---------------------------------------------------------------------------

// Leg 1 decides which identity the acquisition is for: it names the CSR
// subject and the cache key. A leg 2 response naming a different identity is
// not a credential for this request, and filing it under this request's cache
// key would store one identity's certificate under another's name.
func TestIssuedCredentialMustMatchThePlatformMetadata(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*imdsFake)
		wantSub string
	}{
		{
			name:    "client id",
			mutate:  func(f *imdsFake) { f.issueClientID = "11111111-2222-3333-4444-555555555555" },
			wantSub: "client ID",
		},
		{
			name:    "tenant id",
			mutate:  func(f *imdsFake) { f.issueTenantID = "11111111-2222-3333-4444-555555555555" },
			wantSub: "tenant",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withCleanCaches(t)
			fake := newIMDSFake(t)
			tc.mutate(fake)
			client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

			_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
			if err == nil {
				t.Fatal("a credential issued for a different identity was accepted")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error = %v, want it to name the mismatched %s", err, tc.wantSub)
			}
			if fake.countOf("token") != 0 {
				t.Fatal("a token was requested with a credential for the wrong identity")
			}
		})
	}
}

// An identifier that is not a GUID is not an identifier. Both reach a cache
// partition key, a certificate subject and the token request, so the shape is
// checked before any of them.
func TestIdentifiersMustBeGUIDs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*imdsFake)
	}{
		{"metadata client id", func(f *imdsFake) { f.clientID = "not-a-guid" }},
		{"metadata tenant id", func(f *imdsFake) { f.tenantID = "not-a-guid" }},
		{"issued client id", func(f *imdsFake) { f.issueClientID = "not-a-guid" }},
		{"issued tenant id", func(f *imdsFake) { f.issueTenantID = "not-a-guid" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withCleanCaches(t)
			fake := newIMDSFake(t)
			tc.mutate(fake)
			client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

			_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
			if err == nil {
				t.Fatal("a non-GUID identifier was accepted")
			}
			if !strings.Contains(err.Error(), "not a GUID") {
				t.Fatalf("error = %v, want it to say the value is not a GUID", err)
			}
		})
	}
}

// The public key comparison proves the certificate carries this machine's
// binding key. It says nothing about which identity the certificate names, and
// the client ID on the token request comes from the issuance response, so a
// certificate naming somebody else has to be caught separately.
func TestIssuedCertificateMustNameTheIdentity(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.certSubjectCN = "11111111-2222-3333-4444-555555555555"
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("a certificate naming a different identity was accepted")
	}
	if !strings.Contains(err.Error(), "names") {
		t.Fatalf("error = %v, want it to say the certificate names another identity", err)
	}
}

// A certificate that cannot be presented on a client handshake fails at the
// handshake with a TLS alert and no local explanation, and persisting it makes
// every later process pay for the same discovery.
func TestIssuedCertificateMustBeUsableForClientMtls(t *testing.T) {
	serverOnly := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	encipherOnly := x509.KeyUsageKeyEncipherment
	for _, tc := range []struct {
		name    string
		mutate  func(*imdsFake)
		wantSub string
	}{
		{"extended key usage", func(f *imdsFake) { f.certExtKeyUsage = serverOnly }, "extended key usage"},
		{"key usage", func(f *imdsFake) { f.certKeyUsage = &encipherOnly }, "key usage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withCleanCaches(t)
			fake := newIMDSFake(t)
			tc.mutate(fake)
			client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

			_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
			if err == nil {
				t.Fatal("a certificate that cannot authenticate a client handshake was accepted")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error = %v, want it to name the %s", err, tc.wantSub)
			}
		})
	}
}

// An absent extension places no restriction, which is what RFC 5280 says and
// what a certificate issued without either extension means.
func TestCertificateWithoutUsageExtensionsIsAccepted(t *testing.T) {
	leaf := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "8c8a1b0a-4d40-4d9e-9a4f-1f2a3b4c5d6e"},
		NotBefore: now().Add(-time.Hour),
		NotAfter:  now().Add(30 * 24 * time.Hour),
	}
	if err := certificateUsableForClientMtls(leaf); err != nil {
		t.Fatalf("certificateUsableForClientMtls = %v, want an unrestricted certificate to be accepted", err)
	}
	leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	if err := certificateUsableForClientMtls(leaf); err != nil {
		t.Fatalf("certificateUsableForClientMtls = %v, want anyExtendedKeyUsage to be accepted", err)
	}
}

// A certificate that is not valid now cannot carry a token, whichever side of
// its window it is on.
func TestCertificateOutsideItsValidityIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		leaf  *x509.Certificate
		wants string
	}{
		{
			"not yet valid",
			&x509.Certificate{NotBefore: now().Add(time.Hour), NotAfter: now().Add(48 * time.Hour)},
			"not valid until",
		},
		{
			"expired",
			&x509.Certificate{NotBefore: now().Add(-48 * time.Hour), NotAfter: now().Add(-time.Hour)},
			"expired",
		},
		{
			"no expiry",
			&x509.Certificate{NotBefore: now().Add(-time.Hour)},
			"no expiry",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := certificateUsableForClientMtls(tc.leaf)
			if err == nil {
				t.Fatal("an unusable certificate was accepted")
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("error = %v, want it to say %q", err, tc.wants)
			}
		})
	}
}

// A zero NotAfter is not "never expires": it is a certificate whose validity
// could not be read. Treating it as healthy would make a malformed or truncated
// stored certificate the one cache entry that never refreshes.
func TestNeedsRefreshTreatsAnUnreadableExpiryAsDue(t *testing.T) {
	if !needsRefresh(nil) {
		t.Error("a certificate with no leaf should need refreshing")
	}
	if !needsRefresh(&x509.Certificate{}) {
		t.Error("a certificate with a zero NotAfter should need refreshing")
	}
	if needsRefresh(&x509.Certificate{NotAfter: now().Add(30 * 24 * time.Hour)}) {
		t.Error("a long-lived certificate should not need refreshing")
	}
}

// ---------------------------------------------------------------------------
// Identifier comparisons fold case.
// ---------------------------------------------------------------------------

// A persisted certificate's client ID is read back from the subject and
// lower-cased on the way in, while leg 1 returns whatever case IMDS chose. A
// case-sensitive comparison would delete the persisted certificate and re-mint
// on every acquisition against a rate-limited service.
func TestCachedCertificateClientIDComparisonFoldsCase(t *testing.T) {
	withCleanCaches(t)
	provider := newFakeKeyProvider()
	const lower = "8c8a1b0a-4d40-4d9e-9a4f-1f2a3b4c5d6e"
	cert := testBindingCertificate(t, provider, bindingKeyName, now().Add(30*24*time.Hour))
	cert.ClientID = lower
	certCache.adopt("alias", cert)
	t.Cleanup(func() { certCache.clear() })

	got, ok := certCache.usable("alias", strings.ToUpper(lower), strings.ToUpper(cert.TenantID), provider)
	if !ok {
		t.Fatal("an upper-cased client ID did not match the cached certificate")
	}
	_ = got.Close()
}

// An identity can be moved between tenants. The client ID does not change when
// that happens, so a certificate issued for the old tenant still looks like this
// machine's credential on a client-ID comparison alone - while naming an
// authority the token endpoint will no longer honour. Both identifiers are
// therefore compared, and a tenant change drops the entry.
func TestCachedCertificateIsDroppedWhenTheTenantChanges(t *testing.T) {
	withCleanCaches(t)
	provider := newFakeKeyProvider()
	const clientID = "8c8a1b0a-4d40-4d9e-9a4f-1f2a3b4c5d6e"
	const oldTenant = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	const newTenant = "11111111-2222-3333-4444-555555555555"

	cert := testBindingCertificate(t, provider, bindingKeyName, now().Add(30*24*time.Hour))
	cert.ClientID = clientID
	cert.TenantID = oldTenant
	certCache.adopt("alias", cert)
	t.Cleanup(func() { certCache.clear() })

	// Same client ID, different tenant: not this machine's credential any more.
	if got, ok := certCache.usable("alias", clientID, newTenant, provider); ok {
		_ = got.Close()
		t.Fatal("a certificate issued for another tenant was reused")
	}
	// And it is gone, so a later read cannot resurrect it.
	if _, ok := certCache.get("alias"); ok {
		t.Fatal("the mismatched certificate was left in the cache")
	}
}

// The persisted store is checked the same way, and on a mismatch the alias is
// removed so a cold start does not keep restoring a certificate for an identity
// that has moved.
func TestPersistedCertificateIsDroppedWhenTheTenantChanges(t *testing.T) {
	persisted := withCleanCaches(t)
	provider := newFakeKeyProvider()
	const clientID = "8c8a1b0a-4d40-4d9e-9a4f-1f2a3b4c5d6e"
	const oldTenant = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	const newTenant = "11111111-2222-3333-4444-555555555555"

	cert := testBindingCertificate(t, provider, bindingKeyName, now().Add(30*24*time.Hour))
	cert.ClientID = clientID
	cert.TenantID = oldTenant
	persisted.write("alias", cert)
	if _, ok := persisted.read("alias"); !ok {
		t.Fatal("the fixture did not persist a certificate")
	}

	if got, ok := certCache.restore("alias", clientID, newTenant, provider); ok {
		_ = got.Close()
		t.Fatal("a persisted certificate for another tenant was restored")
	}
	if _, ok := persisted.read("alias"); ok {
		t.Fatal("the persisted alias was left behind after a tenant change")
	}
}

// The tenant comparison folds case for the same reason the client ID one does:
// both are GUIDs and IMDS is not consistent about how it renders them, so a
// case-sensitive check would re-mint on every acquisition.
func TestCachedCertificateTenantComparisonFoldsCase(t *testing.T) {
	withCleanCaches(t)
	provider := newFakeKeyProvider()
	const clientID = "8c8a1b0a-4d40-4d9e-9a4f-1f2a3b4c5d6e"
	const tenant = "72f988bf-86f1-41af-91ab-2d7cd011db47"

	cert := testBindingCertificate(t, provider, bindingKeyName, now().Add(30*24*time.Hour))
	cert.ClientID = clientID
	cert.TenantID = tenant
	certCache.adopt("alias", cert)
	t.Cleanup(func() { certCache.clear() })

	got, ok := certCache.usable("alias", strings.ToUpper(clientID), strings.ToUpper(tenant), provider)
	if !ok {
		t.Fatal("an upper-cased tenant did not match the cached certificate")
	}
	_ = got.Close()
}

// A bearer request answered with anything else has been given a credential the
// caller does not know how to spend: WithRequestOverMtls promises a token any
// resource accepts, and a caller relying on that sends it with the Bearer
// scheme whatever the service said.
func TestTokenTypeIsCheckedInBothDirections(t *testing.T) {
	for _, tc := range []struct {
		name     string
		override string
		option   AcquireTokenOption
		wants    string
	}{
		{"bound request answered with bearer", "Bearer", WithMtlsProofOfPossession(), "certificate-bound token was requested"},
		{"bearer request answered with bound", "mtls_pop", WithRequestOverMtls(), "bearer token was requested"},
		{"bearer request answered with an unknown type", "something_else", WithRequestOverMtls(), "bearer token was requested"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withCleanCaches(t)
			fake := newIMDSFake(t)
			fake.tokenTypeOverride = tc.override
			client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

			_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", tc.option)
			if err == nil {
				t.Fatal("a token of the wrong type was accepted")
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("error = %v, want it to say %q", err, tc.wants)
			}
		})
	}
}

// The spelling of the type is not part of the contract: RFC 6749 declares
// token_type case-insensitive, so a service answering "bearer" satisfies a
// bearer request.
func TestTokenTypeComparisonFoldsCase(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.tokenTypeOverride = "bEaReR"
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithRequestOverMtls()); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The token response has to be an answer.
// ---------------------------------------------------------------------------

// A 200 that parses but carries no token would be written to the cache and
// handed back, so every later request would be served an empty access token
// until it expired.
func TestTokenResponseMustCarryTheRequiredFields(t *testing.T) {
	for _, tc := range []struct {
		name  string
		body  string
		wants string
	}{
		{"no access token", `{"token_type":"Bearer","expires_in":3599}`, "no access_token"},
		{"no token type", `{"access_token":"t","expires_in":3599}`, "no token_type"},
		{"no expiry", `{"access_token":"t","token_type":"Bearer"}`, "expires_in"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withCleanCaches(t)
			fake := newIMDSFake(t)
			fake.tokenBody = tc.body
			client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

			_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithRequestOverMtls())
			if err == nil {
				t.Fatal("an incomplete token response was accepted")
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("error = %v, want it to say %q", err, tc.wants)
			}
		})
	}
}

// A body read to exactly the limit is indistinguishable from a truncated one,
// and a truncation that lands after the last field this package reads would
// parse. Reading one byte past the limit is what tells the two apart.
func TestOversizedBodiesAreRefusedRatherThanTruncated(t *testing.T) {
	oversized := strings.Repeat("a", imdsMaxResponseBody+1)
	if _, err := readBoundedBody(strings.NewReader(oversized), "the test body"); err == nil {
		t.Fatal("a body past the limit was accepted")
	}
	atLimit := strings.Repeat("a", imdsMaxResponseBody)
	body, err := readBoundedBody(strings.NewReader(atLimit), "the test body")
	if err != nil {
		t.Fatalf("a body exactly at the limit was refused: %v", err)
	}
	if len(body) != imdsMaxResponseBody {
		t.Fatalf("read %d bytes, want %d", len(body), imdsMaxResponseBody)
	}
}

// ---------------------------------------------------------------------------
// Re-minting is narrow.
// ---------------------------------------------------------------------------

// Re-minting discards a valid certificate, deletes the persisted copy shared
// with MSAL .NET, and spends an /issuecredential call against a rate-limited
// service. Only a failure that names the certificate is worth that.
func TestRemintTriggersAreCertificateSpecific(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"invalid_client", &entraTokenError{StatusCode: 401, Code: "invalid_client"}, true},
		{"binding key cannot sign", errors.New(bindingKeySignFailureMarker + ": NCryptSignHash failed"), true},
		{"bad certificate alert", errors.New("remote error: tls: bad certificate"), true},
		{"certificate required alert", errors.New("remote error: tls: certificate required"), true},
		// A reset is what a proxy, a firewall, a draining load balancer, an idle
		// pooled connection and a service restart all produce. None says
		// anything about the certificate.
		{"connection reset", errors.New("read tcp 10.0.0.1:443: connection reset by peer"), false},
		// handshake_failure is what a server sends when it cannot agree on a
		// protocol version or a cipher suite.
		{"generic handshake failure", errors.New("remote error: tls: handshake failure"), false},
		{"server chain not trusted", errors.New("x509: certificate signed by unknown authority"), false},
		{"invalid_request", &entraTokenError{StatusCode: 400, Code: "invalid_request"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldRemintCertificate(tc.err); got != tc.want {
				t.Fatalf("shouldRemintCertificate(%v) = %t, want %t", tc.err, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Custom mTLS clients.
// ---------------------------------------------------------------------------

// A factory that returns nothing leaves no client to send the request on.
// Returning a named error is what turns that into something a caller can read
// rather than a panic inside net/http.
func TestNilMtlsClientFactoryIsAnError(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())
	// Set after newTestClient, which installs its own factory to trust the
	// fake's self-signed certificate and would otherwise overwrite the option.
	client.mtlsClientFactory = func(tls.Certificate) *http.Client { return nil }

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if !errors.Is(err, ErrMtlsClientFactoryReturnedNil) {
		t.Fatalf("AcquireToken = %v, want ErrMtlsClientFactoryReturnedNil", err)
	}
}

// A nil CheckRedirect is Go's default, which follows up to ten redirects. On
// this leg that would replay the client credential at whatever host the
// Location header names and offer the binding certificate on the cloned
// handshake, so the refusal is installed on a copy of the caller's client.
func TestCustomMtlsClientGetsARedirectRefusalWithoutBeingMutated(t *testing.T) {
	caller := &http.Client{}
	c := Client{mtlsClientFactory: func(tls.Certificate) *http.Client { return caller }}

	got, err := c.mtlsClient(tls.Certificate{})
	if err != nil {
		t.Fatalf("mtlsClient: %v", err)
	}
	if got == caller {
		t.Fatal("the caller's client was used directly, so installing a policy would have mutated it")
	}
	if got.CheckRedirect == nil {
		t.Fatal("no redirect policy was installed on a client that stated none")
	}
	if caller.CheckRedirect != nil {
		t.Fatal("the caller's own client was mutated")
	}
	if err := got.CheckRedirect(mustRequest(t, "https://elsewhere.example/"), nil); err == nil {
		t.Fatal("the installed policy followed a redirect")
	}

	// A caller who stated a policy has said what they want, and MSAL does not
	// override explicit configuration.
	stated := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	c = Client{mtlsClientFactory: func(tls.Certificate) *http.Client { return stated }}
	got, err = c.mtlsClient(tls.Certificate{})
	if err != nil {
		t.Fatalf("mtlsClient: %v", err)
	}
	if got != stated {
		t.Fatal("a caller's explicit redirect policy was replaced")
	}
}

// ---------------------------------------------------------------------------
// Operator-controlled endpoint allowlist.
// ---------------------------------------------------------------------------

// Unset, nothing changes: IMDS is trusted for these values exactly as before,
// because there is no cloud metadata here to derive a default from and a
// public-cloud list would break sovereign and private deployments.
func TestAllowedHostsUnsetImposesNoRestriction(t *testing.T) {
	t.Setenv(imdsV2AllowedHostsEnvVar, "")
	m := csrMetadata{AttestationEndpoint: "https://maa.sovereign.example"}
	if _, err := m.attestationURL(); err != nil {
		t.Fatalf("attestationURL = %v, want no restriction when the allowlist is unset", err)
	}
}

// Set, it is fail-closed for both credential-bearing destinations IMDS names.
func TestAllowedHostsIsEnforcedWhenSet(t *testing.T) {
	t.Setenv(imdsV2AllowedHostsEnvVar, "*.attest.azure.net, mtlsauth.contoso.example")

	for _, tc := range []struct {
		endpoint string
		allowed  bool
	}{
		{"https://sharedeus.eus.attest.azure.net", true},
		{"https://attest.azure.net", true},
		{"https://notattest.azure.net", false},
		{"https://attacker.example", false},
	} {
		m := csrMetadata{AttestationEndpoint: tc.endpoint}
		_, err := m.attestationURL()
		if tc.allowed && err != nil {
			t.Errorf("attestationURL(%q) = %v, want it allowed", tc.endpoint, err)
		}
		if !tc.allowed && err == nil {
			t.Errorf("attestationURL(%q) was allowed, want it refused", tc.endpoint)
		}
	}

	for _, tc := range []struct {
		endpoint string
		allowed  bool
	}{
		{"https://mtlsauth.contoso.example", true},
		{"https://mtlsauth.attacker.example", false},
	} {
		b := &bindingCertificate{Endpoint: tc.endpoint, TenantID: "72f988bf-86f1-41af-91ab-2d7cd011db47"}
		_, err := b.tokenEndpoint()
		if tc.allowed && err != nil {
			t.Errorf("tokenEndpoint(%q) = %v, want it allowed", tc.endpoint, err)
		}
		if !tc.allowed && err == nil {
			t.Errorf("tokenEndpoint(%q) was allowed, want it refused", tc.endpoint)
		}
	}
}

// ---------------------------------------------------------------------------
// Capability discovery is per configuration.
// ---------------------------------------------------------------------------

// A Client can carry its own HTTP client, key provider and metadata endpoint,
// all of which decide what discovery finds. One shared entry would let the
// first client to ask publish its answer to every other client in the process.
func TestCapabilitiesAreNotSharedBetweenDifferentClients(t *testing.T) {
	withCleanCaches(t)
	capable := newIMDSFake(t)
	capableClient := capable.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	caps, err := capableClient.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if caps.MaxSupportedBindingStrength != MtlsBindingStrengthKeyGuard {
		t.Fatalf("the capable host reported %s, want KeyGuard", caps.MaxSupportedBindingStrength)
	}

	// A second client whose key provider cannot produce a KeyGuard key must get
	// its own answer rather than the first client's.
	weakProvider := newFakeKeyProvider()
	weakProvider.typ = keyTypeSoftware
	weakClient := capable.newTestClient(t, SystemAssigned(), weakProvider)
	weakCaps, err := weakClient.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if weakCaps.MaxSupportedBindingStrength != MtlsBindingStrengthSoftware {
		t.Fatalf("the second client reported %s, want Software: it was served another client's answer",
			weakCaps.MaxSupportedBindingStrength)
	}

	// Each client holds its own state, and neither points at the other's.
	if capableClient.hostCapabilities == nil || weakClient.hostCapabilities == nil {
		t.Fatal("New did not give a client its own capabilities state")
	}
	if capableClient.hostCapabilities == weakClient.hostCapabilities {
		t.Fatal("two independently constructed clients share one capabilities state")
	}

	// The first client's answer must survive the second client's discovery,
	// which is what a shared entry would have overwritten.
	again, err := capableClient.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if again.MaxSupportedBindingStrength != MtlsBindingStrengthKeyGuard {
		t.Fatalf("the capable client now reports %s: another client's discovery overwrote its answer",
			again.MaxSupportedBindingStrength)
	}
}

// A definitive answer is kept for the life of the client, so a client that is
// discarded must take that answer with it. Nothing may accumulate in package
// state, both because a long-lived process would leak an entry per client and
// because an entry outliving the client it describes is what allows a later,
// unrelated client to be handed it.
func TestCapabilitiesStateIsNotRetainedProcessWide(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)

	var seen []*capabilitiesState
	for i := 0; i < 3; i++ {
		client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())
		if _, err := client.Capabilities(context.Background()); err != nil {
			t.Fatalf("Capabilities: %v", err)
		}
		for _, prior := range seen {
			if prior == client.hostCapabilities {
				t.Fatal("a newly constructed client was given a previous client's capabilities state")
			}
		}
		seen = append(seen, client.hostCapabilities)
	}

	// Each client probed for itself rather than reading a shared answer, which
	// is the observable consequence of not sharing state.
	if got := fake.countOf("metadata"); got < len(seen) {
		t.Fatalf("%d metadata probes for %d independent clients: an answer was shared", got, len(seen))
	}
}

// Two copies of one client are the same client, so they share an answer. That
// is what keeps the single-flight useful for a Client that callers copy by
// value - which every method on Client does, since they all take it by value.
func TestCapabilitiesAreSharedBetweenCopiesOfOneClient(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	client := fake.newTestClient(t, SystemAssigned(), provider)

	if _, err := client.Capabilities(context.Background()); err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	probes := fake.countOf("metadata")

	copyOfClient := client
	if copyOfClient.hostCapabilities != client.hostCapabilities {
		t.Fatal("a value copy of a client did not carry its capabilities state")
	}
	if _, err := copyOfClient.Capabilities(context.Background()); err != nil {
		t.Fatalf("Capabilities on a copy: %v", err)
	}
	if got := fake.countOf("metadata"); got != probes {
		t.Fatalf("a copy of the same client probed again (%d then %d)", probes, got)
	}

	// A copy taken before the original discovered anything still shares the
	// result, because the state is allocated by New rather than on first use.
	fresh := fake.newTestClient(t, SystemAssigned(), provider)
	early := fresh
	if _, err := fresh.Capabilities(context.Background()); err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	before := fake.countOf("metadata")
	if _, err := early.Capabilities(context.Background()); err != nil {
		t.Fatalf("Capabilities on an early copy: %v", err)
	}
	if got := fake.countOf("metadata"); got != before {
		t.Fatalf("a copy taken before discovery probed again (%d then %d)", before, got)
	}
}

// A Client that was not built by New has no state to cache in. It must still
// answer correctly rather than panic, and must not fall back to sharing
// anything with another client.
func TestCapabilitiesOnAClientWithoutStateStillAnswers(t *testing.T) {
	withCleanCaches(t)
	var zero Client
	if zero.hostCapabilities != nil {
		t.Fatal("a zero-value Client should carry no capabilities state")
	}
	if state := zero.hostCapabilityState(); state == nil {
		t.Fatal("hostCapabilityState returned nil for a zero-value Client")
	}
	if a, b := zero.hostCapabilityState(), zero.hostCapabilityState(); a == b {
		t.Fatal("a stateless Client was given a shared fallback state")
	}
	// Source is empty on a zero-value Client, which discoverCapabilities treats
	// as an environment-configured source that cannot bind.
	caps, err := zero.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if caps.MaxSupportedBindingStrength != MtlsBindingStrengthNone {
		t.Fatalf("MaxSupportedBindingStrength = %s, want None", caps.MaxSupportedBindingStrength)
	}
}

// ---------------------------------------------------------------------------
// The exported strength enum.
// ---------------------------------------------------------------------------

// MtlsBindingStrength is an exported integer type, so nothing in the type
// system stops a caller passing the reserved 2 or an arbitrary number. Such a
// value cannot be a floor.
func TestUndeclaredMinStrengthIsRejected(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	for _, strength := range []MtlsBindingStrength{2, 4, -1} {
		_, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
			WithMtlsProofOfPossession(), WithMtlsPoPMinStrength(strength))
		if !errors.Is(err, ErrInvalidMtlsBindingStrength) {
			t.Errorf("AcquireToken with strength %d = %v, want ErrInvalidMtlsBindingStrength", int(strength), err)
		}
	}
	for _, strength := range []MtlsBindingStrength{
		MtlsBindingStrengthNone, MtlsBindingStrengthSoftware, MtlsBindingStrengthKeyGuard,
	} {
		if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
			WithMtlsProofOfPossession(), WithMtlsPoPMinStrength(strength)); errors.Is(err, ErrInvalidMtlsBindingStrength) {
			t.Errorf("a declared tier %s was rejected", strength)
		}
	}
}

// ---------------------------------------------------------------------------
// Proactive refresh must not cost a cache hit anything.
// ---------------------------------------------------------------------------

// A caller holding a usable token that is due a proactive refresh already has
// its answer. Queueing it behind another acquisition would turn a cache hit
// into a wait as long as a full cold acquisition.
func TestProactiveRefreshDoesNotWaitOnTheTokenGate(t *testing.T) {
	release, ok := tryAcquireMITokenGate()
	if !ok {
		t.Fatal("the token gate was already held")
	}
	defer release()

	if _, ok := tryAcquireMITokenGate(); ok {
		t.Fatal("the gate was taken twice")
	}

	// The blocking form still waits, and still honours its context, which is
	// what an ordinary cold acquisition needs.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := acquireMITokenGate(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("acquireMITokenGate = %v, want it to wait and then give up", err)
	}
}

// miTokenGate is process-wide and nothing but a release ever drains it, so a
// release skipped while unwinding is not a lost refresh: it is a permanent
// stall in which every later acquisition in the process blocks until its own
// context expires. A caller-supplied HTTP client is arbitrary code, and a
// server that recovers panics per request keeps the process alive in that
// broken state, so the release has to survive a panic rather than merely an
// error.
func TestProactiveRefreshReleasesTheGateEvenOnPanic(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())
	client.httpClient = panickingHTTPClient{}

	func() {
		defer func() {
			if recover() == nil {
				t.Error("the fixture did not panic, so this test proves nothing")
			}
		}()
		_, _ = client.refreshWithoutWaiting(context.Background(), "https://vault.azure.net", AcquireTokenOptions{})
	}()

	held, ok := tryAcquireMITokenGate()
	if !ok {
		t.Fatal("the process-wide token gate was left held after a panic, stalling every later acquisition")
	}
	held()
}

// panickingHTTPClient stands in for a caller-supplied client that faults. It
// panics rather than returning an error because an error is already covered by
// the ordinary failure path; what is under test is unwinding.
type panickingHTTPClient struct{}

func (panickingHTTPClient) Do(*http.Request) (*http.Response, error) {
	panic("managedidentity test: the caller's HTTP client faulted")
}

func (panickingHTTPClient) CloseIdleConnections() {}

// ---------------------------------------------------------------------------
// Retry schedule.
// ---------------------------------------------------------------------------

// MSAL .NET fixes the schedule from the first answer. Pinning only the count
// would produce a hybrid neither library implements: 410's ten attempts run at
// exponential backoff the moment a later answer was a 500.
func TestRetryScheduleIsPinnedByTheFirstAnswer(t *testing.T) {
	for _, tc := range []struct {
		name      string
		statuses  []int
		wantWaits []time.Duration
	}{
		{
			name:      "410 then 500 keeps the linear schedule",
			statuses:  []int{http.StatusGone, http.StatusInternalServerError, http.StatusOK},
			wantWaits: []time.Duration{imdsGoneRetryAfter, imdsGoneRetryAfter},
		},
		{
			name:      "500 then 410 keeps the exponential schedule",
			statuses:  []int{http.StatusInternalServerError, http.StatusGone, http.StatusOK},
			wantWaits: []time.Duration{imdsRetryDelay(0), imdsRetryDelay(1)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var waits []time.Duration
			originalWait := retryWait
			retryWait = func(_ context.Context, d time.Duration) error {
				waits = append(waits, d)
				return nil
			}
			t.Cleanup(func() { retryWait = originalWait })

			attempt := 0
			client := stubHTTPClient(func(*http.Request) (*http.Response, error) {
				status := tc.statuses[len(tc.statuses)-1]
				if attempt < len(tc.statuses) {
					status = tc.statuses[attempt]
				}
				attempt++
				return &http.Response{StatusCode: status, Body: http.NoBody, Header: http.Header{}}, nil
			})

			req, err := http.NewRequest(http.MethodGet, "http://169.254.169.254/metadata", nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := sendIMDSRequest(context.Background(), client, req, true, imdsRetriableStatus); err != nil {
				t.Fatalf("sendIMDSRequest: %v", err)
			}
			if len(waits) != len(tc.wantWaits) {
				t.Fatalf("waited %v, want %v", waits, tc.wantWaits)
			}
			for i := range waits {
				if waits[i] != tc.wantWaits[i] {
					t.Fatalf("wait %d = %v, want %v (waits: %v)", i, waits[i], tc.wantWaits[i], waits)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

// stubHTTPClient is an ops.HTTPClient that answers from a function. It is
// deliberately not an *http.Client, which also proves sendIMDSRequest leaves a
// client it cannot clone alone rather than failing on it.
type stubHTTPClient func(*http.Request) (*http.Response, error)

func (f stubHTTPClient) Do(req *http.Request) (*http.Response, error) { return f(req) }
func (f stubHTTPClient) CloseIdleConnections()                        {}

func mustRequest(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// testBindingCertificate builds a certificate bound to the key the provider
// holds under keyName. Passing a name other than bindingKeyName is how a test
// produces the certificate a cache entry becomes after the container behind it
// was reset: it still parses, and its key is simply not there any more.
func testBindingCertificate(t *testing.T, provider *fakeKeyProvider, keyName string, notAfter time.Time) *bindingCertificate {
	t.Helper()
	key, err := provider.getOrCreateKey(keyName)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = key.Close() })

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "8c8a1b0a-4d40-4d9e-9a4f-1f2a3b4c5d6e"},
		NotBefore:    now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	signer, ok := key.Signer.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("the fake provider handed back a %T", key.Signer)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &signer.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return newBindingCertificate(der, leaf, key, certificateRequestResponse{
		ClientID: "8c8a1b0a-4d40-4d9e-9a4f-1f2a3b4c5d6e",
		TenantID: "72f988bf-86f1-41af-91ab-2d7cd011db47",
	})
}
