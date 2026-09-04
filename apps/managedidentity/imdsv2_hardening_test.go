// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package managedidentity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// revocableSigner is a software key whose handle can be released, the way a CNG
// handle is. Signing after the release fails, which is what makes a
// use-after-close observable in a test that has no KeyGuard available.
type revocableSigner struct {
	key    *rsa.PrivateKey
	mu     sync.Mutex
	closed bool
}

func (r *revocableSigner) Public() crypto.PublicKey { return r.key.Public() }

func (r *revocableSigner) Sign(rnd io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return nil, errors.New("key handle is closed")
	}
	return r.key.Sign(rnd, digest, opts)
}

func (r *revocableSigner) close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

// revocableKeyProvider hands out revocableSigner handles over one key.
type revocableKeyProvider struct {
	mu  sync.Mutex
	key *rsa.PrivateKey
}

func (p *revocableKeyProvider) getOrCreateKey(string) (bindingKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.key == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return bindingKey{}, err
		}
		p.key = key
	}
	signer := &revocableSigner{key: p.key}
	return bindingKey{Signer: signer, Type: keyTypeKeyGuard, Close: signer.close}, nil
}

func (p *revocableKeyProvider) deleteKey(string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key = nil
	return nil
}

// countCalls reports how many times the fake saw a given leg.
func (f *imdsFake) countCalls(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == path {
			n++
		}
	}
	return n
}

func TestIMDSv2AttestationWithoutMtlsIsRejected(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	attempts := withStubAttestation(t, "token", nil)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	// Attestation only means something on the mTLS path. Asking for it on a
	// plain bearer request used to be silently ignored, which handed back a
	// credential with fewer guarantees than the caller asked for.
	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithAttestationSupport())
	if !errors.Is(err, ErrAttestationRequiresMtls) {
		t.Fatalf("error = %v, want ErrAttestationRequiresMtls", err)
	}
	if fake.callCount() != 0 {
		t.Fatal("an invalid option combination reached the network")
	}
	if *attempts != 0 {
		t.Fatal("attestation was attempted for a request that could not carry it")
	}
}

func TestIMDSv2AttestationIsAcceptedWithBearerOverMtls(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.tokenType = "Bearer"
	attempts := withStubAttestation(t, stubAttestationJWT(t, time.Now().Add(time.Hour)), nil)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	// WithRequestOverMtls still runs the certificate-authenticated exchange, so
	// attestation is meaningful there and must not be rejected.
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithRequestOverMtls(), WithAttestationSupport()); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if *attempts != 1 {
		t.Fatalf("attestation attempts = %d, want 1", *attempts)
	}
	if fake.attestationToken() == "" {
		t.Fatal("the issue request carried no attestation token")
	}
}

func TestIMDSv2BearerOverMtlsReturnsNoBindingCertificate(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.tokenType = "Bearer"
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	result, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithRequestOverMtls())
	if err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	// The token is not bound to the certificate, so the caller has nothing to
	// present and is given nothing to present. This pins the documented
	// contract, which previously disagreed with the code.
	if result.BindingCertificate != nil {
		t.Fatal("a bearer-over-mTLS acquisition returned a binding certificate")
	}
}

func TestIMDSv2BindingCertificateOutlivesCacheEviction(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), &revocableKeyProvider{})

	result, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if result.BindingCertificate == nil {
		t.Fatal("no binding certificate was returned")
	}
	signer, ok := result.BindingCertificate.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatal("the binding certificate's private key is not a signer")
	}

	// Anything that drops the cache entry releases the cache's reference to the
	// key. The certificate already handed to the caller must keep working: it is
	// what they present on the TLS handshake to the resource, and that handshake
	// can happen long after a re-mint or an identity change evicted the entry.
	certCache.clear()

	digest := sha256.Sum256([]byte("payload the caller signs after eviction"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("signing with the returned certificate failed after the cache was evicted: %v", err)
	}
}

func TestIMDSv2SeparateIdentitiesGetSeparateCertificates(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	first := fake.newTestClient(t, UserAssignedClientID("11111111-1111-1111-1111-111111111111"), provider)
	firstResult, err := first.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}

	second := fake.newTestClient(t, UserAssignedClientID("22222222-2222-2222-2222-222222222222"), provider)
	fake.resetCalls()
	secondResult, err := second.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}

	// A second identity must mint its own certificate rather than be served the
	// first identity's, which would let one identity present a credential
	// issued for another.
	if got := strings.Join(fake.calls, ","); got != "metadata,issue,token" {
		t.Fatalf("call sequence = %q, want a second identity to get its own certificate", got)
	}
	if firstResult.BindingCertificate == nil || secondResult.BindingCertificate == nil {
		t.Fatal("a binding certificate was missing")
	}
	if string(firstResult.BindingCertificate.Certificate[0]) == string(secondResult.BindingCertificate.Certificate[0]) {
		t.Fatal("two identities were handed the same binding certificate")
	}

	// The first identity's certificate must still be cached and reusable.
	fake.resetCalls()
	if _, err := first.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("third AcquireToken: %v", err)
	}
	if got := strings.Join(fake.calls, ","); got != "metadata,token" {
		t.Fatalf("call sequence = %q, want the first identity's certificate to be reused", got)
	}
}

func TestIMDSv2ReissuesCertificateNearingExpiry(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	// Well inside bindingCertRefreshWindow, so the certificate is already too
	// close to expiry to be worth presenting.
	fake.certLifetime = time.Minute
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}

	fake.resetCalls()
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if got := strings.Join(fake.calls, ","); got != "metadata,issue,token" {
		t.Fatalf("call sequence = %q, want a certificate near expiry to be re-minted", got)
	}
}

// A certificate that is already inside the refresh window is used for the
// request that minted it but must not be stored: a later caller would reject it
// on read, so caching it would pin a key handle open for nothing. The
// reissue test above passes with or without the write-side guard, because the
// read-side check also forces a re-mint, so the cache is inspected directly.
func TestIMDSv2DoesNotCacheACertificateBornInsideTheRefreshWindow(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.certLifetime = time.Minute
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}

	certCache.mu.Lock()
	cached := len(certCache.entries)
	certCache.mu.Unlock()
	if cached != 0 {
		t.Errorf("the certificate cache holds %d entries, want a certificate inside the refresh window not to be stored", cached)
	}
}

func TestIMDSv2ReusesCertificateOutsideRefreshWindow(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.certLifetime = 30 * 24 * time.Hour
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}

	// The mirror of the test above: a certificate comfortably inside its
	// lifetime must not be re-minted, or every acquisition pays for issuance.
	fake.resetCalls()
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if got := strings.Join(fake.calls, ","); got != "metadata,token" {
		t.Fatalf("call sequence = %q, want a healthy certificate to be reused", got)
	}
}

func TestIMDSv2CachedTokenIsNotServedWithAnOrphanedCertificate(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	client := fake.newTestClient(t, SystemAssigned(), provider)

	const resource = "https://vault.azure.net"
	if _, err := client.AcquireToken(context.Background(), resource, WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}

	// The isolated container was recreated, so the cached certificate no longer
	// matches the key. Asking for the same resource takes the cached-token fast
	// path, which must still notice: handing back a bound token with a
	// certificate whose key is gone fails later, in the caller's TLS handshake
	// against the resource, where it is very hard to attribute.
	provider.rotate(t, bindingKeyName)

	fake.resetCalls()
	result, err := client.AcquireToken(context.Background(), resource, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if got := strings.Join(fake.calls, ","); got != "metadata,issue,token" {
		t.Fatalf("call sequence = %q, want the orphaned certificate to be replaced", got)
	}
	if result.BindingCertificate == nil {
		t.Fatal("no binding certificate was returned")
	}
	current, err := provider.getOrCreateKey(bindingKeyName)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = current.Close() }()
	if err := certificateMatchesKey(result.BindingCertificate.Leaf, current); err != nil {
		t.Fatalf("the returned certificate does not match the current key: %v", err)
	}
}

func TestIMDSv2ConcurrentAcquisitionsMintOneCertificate(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	const goroutines = 8
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = client.AcquireToken(context.Background(),
				"https://vault.azure.net", WithMtlsProofOfPossession())
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	// Issuance is serialized because concurrent callers would otherwise each
	// mint a key into the same container and invalidate each other's
	// certificate. Run under -race to also cover the cache mutexes.
	if got := fake.countCalls("issue"); got != 1 {
		t.Fatalf("issue requests = %d, want exactly 1", got)
	}
}

func TestIMDSv2ConcurrentAttestedAndPlainAcquisitions(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	withStubAttestation(t, stubAttestationJWT(t, time.Now().Add(time.Hour)), nil)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := 0; i < len(errs); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			opts := []AcquireTokenOption{WithMtlsProofOfPossession()}
			if i%2 == 0 {
				opts = append(opts, WithAttestationSupport())
			}
			_, errs[i] = client.AcquireToken(context.Background(), "https://vault.azure.net", opts...)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	// The attested and non-attested certificates live in separate cache
	// partitions, so exactly two are minted no matter how the calls interleave.
	if got := fake.countCalls("issue"); got != 2 {
		t.Fatalf("issue requests = %d, want one per cache partition", got)
	}
}

func TestIMDSv2RejectsHostileAttestationEndpoint(t *testing.T) {
	for _, test := range []struct {
		name     string
		endpoint string
		want     string
	}{
		{"plaintext", "http://attacker.example", "non-https"},
		{"scheme relative", "//attacker.example", "no host"},
		{"no host", "https:///path", "no host"},
		{"empty", "", "no attestationEndpoint"},
	} {
		t.Run(test.name, func(t *testing.T) {
			withCleanCaches(t)
			fake := newIMDSFake(t)
			fake.attestationEndpoint = test.endpoint
			attempts := withStubAttestation(t, "token", nil)
			client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

			// Legs 1 and 2 are unauthenticated plain HTTP, so the endpoint is
			// attacker-influenceable. The native library fetches a managed
			// identity token for this call, so following an arbitrary endpoint
			// would hand that token to whoever answered.
			_, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
				WithMtlsProofOfPossession(), WithAttestationSupport())
			if err == nil {
				t.Fatal("a hostile attestation endpoint was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want it to mention %q", err, test.want)
			}
			if *attempts != 0 {
				t.Fatal("attestation was attempted against an unvalidated endpoint")
			}
		})
	}
}

func TestIMDSv2AcceptsBareHostAttestationEndpoint(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	// IMDS has been observed returning a bare host. That is not a downgrade, so
	// it is accepted and normalized to https rather than rejected.
	fake.attestationEndpoint = "attestation.example"
	var seen string
	original := attestKeyGuardFn
	attestKeyGuardFn = func(endpoint, clientID string, key bindingKey) (string, error) {
		seen = endpoint
		return stubAttestationJWT(t, time.Now().Add(time.Hour)), nil
	}
	t.Cleanup(func() { attestKeyGuardFn = original })
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if seen != "https://attestation.example" {
		t.Fatalf("attestation endpoint = %q, want it normalized to https", seen)
	}
}

func TestIMDSv2NormalizesAttestationEndpointToTheValidatedOrigin(t *testing.T) {
	// The native library parses this URL a second time with C++ rules. Anything
	// handed to it must therefore be the origin net/url actually validated, not
	// the string that happened to pass validation: a parser that folds
	// backslashes to slashes reads "https:/\/\attacker.example" as
	// attacker.example, while net/url reads its host as "https". Returning the
	// rebuilt origin closes that gap.
	//
	// Every case states which of the two defences is meant to catch it. An
	// endpoint with no host at all never reaches the native library, and one
	// that does reach it must arrive as the bare origin. Without that
	// distinction the test passes when attestation is skipped entirely, which
	// hides a change that stops normalizing and starts rejecting instead.
	for _, test := range []struct {
		name     string
		endpoint string
		// want is the exact origin the native library must be handed, or empty
		// when the endpoint has to be rejected before it gets there.
		want string
	}{
		{"backslash authority", `https:/\/\attacker.example`, ""},
		{"single backslash", `https:/\attacker.example`, ""},
		{"userinfo host takeover", "https://attestation.example@attacker.example", ""},
		{"path is dropped", "https://attestation.example/../attacker.example", "https://attestation.example"},
		{"query is dropped", "https://attestation.example/?next=attacker.example", "https://attestation.example"},
		{"fragment is dropped", "https://attestation.example/#attacker.example", "https://attestation.example"},
	} {
		t.Run(test.name, func(t *testing.T) {
			withCleanCaches(t)
			fake := newIMDSFake(t)
			fake.attestationEndpoint = test.endpoint
			var seen string
			var attested bool
			original := attestKeyGuardFn
			attestKeyGuardFn = func(endpoint, clientID string, key bindingKey) (string, error) {
				seen = endpoint
				attested = true
				return stubAttestationJWT(t, time.Now().Add(time.Hour)), nil
			}
			t.Cleanup(func() { attestKeyGuardFn = original })
			client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

			_, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
				WithMtlsProofOfPossession(), WithAttestationSupport())

			if strings.Contains(seen, "attacker.example") {
				t.Fatalf("the native library was handed %q, which carries the attacker's host", seen)
			}
			if test.want == "" {
				if attested {
					t.Fatalf("the native library was called with %q, but an endpoint with no host must be rejected first", seen)
				}
				if err == nil {
					t.Fatal("AcquireToken succeeded, but an unusable attestation endpoint has to fail the acquisition")
				}
				return
			}
			if err != nil {
				t.Fatalf("AcquireToken: %v", err)
			}
			if !attested {
				t.Fatal("the native library was never called, so nothing about the endpoint it receives was proven")
			}
			if seen != test.want {
				t.Fatalf("endpoint = %q, want the bare validated origin %q", seen, test.want)
			}
		})
	}
}

func TestIMDSv2RejectsMalformedMetadata(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		want string
	}{
		{"not json", `{"cuId":`, "parsing platform metadata"},
		{"no client id", `{"cuId":{"vmId":"vm-1"},"tenantId":"t"}`, "clientId"},
		{"no tenant id", `{"cuId":{"vmId":"vm-1"},"clientId":"c"}`, "tenantId"},
		{"no cuid", `{"clientId":"c","tenantId":"t"}`, "vmId"},
	} {
		t.Run(test.name, func(t *testing.T) {
			withCleanCaches(t)
			fake := newIMDSFake(t)
			fake.metadataBody = test.body
			client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

			_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
			if err == nil {
				t.Fatal("malformed platform metadata was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want it to mention %q", err, test.want)
			}
			if fake.countCalls("issue") != 0 {
				t.Fatal("a certificate was requested from malformed metadata")
			}
		})
	}
}

func TestIMDSv2PropagatesContextCancellation(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.AcquireToken(ctx, "https://vault.azure.net", WithMtlsProofOfPossession())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if fake.countCalls("issue") != 0 {
		t.Fatal("a certificate was requested on a cancelled context")
	}
}

func TestIMDSv2ReportsUnreachableMetadataService(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())
	// The service is gone, which is what a host without IMDS looks like.
	fake.metadataServer.Close()

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err == nil {
		t.Fatal("an unreachable metadata service produced a token")
	}
}

func TestIMDSv2ReusesOneHTTPClientPerCertificate(t *testing.T) {
	cert := selfSignedTLSCertificate(t)
	first := mtlsHTTPClient(cert)
	again := mtlsHTTPClient(cert)
	// A fresh client per acquisition strands an idle TLS connection for the
	// transport's idle timeout on every token request.
	if first != again {
		t.Fatal("the same certificate produced two clients")
	}

	third := mtlsHTTPClient(selfSignedTLSCertificate(t))
	if third == first {
		t.Fatal("a different certificate reused the previous client, so a pooled connection could carry the wrong certificate")
	}
}

func TestIMDSv2BindingCertificateSurvivesCallerValueCopy(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), &revocableKeyProvider{})

	// Callers copy the certificate by value — the README sample and the
	// GetClientCertificate callback both do. Once they have, the *tls.Certificate
	// this package returned is unreachable, so any release tied to that pointer
	// runs while the copy is still the thing presenting the key on a handshake.
	signer := func() crypto.Signer {
		result, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
		if err != nil {
			t.Fatalf("AcquireToken: %v", err)
		}
		cert := *result.BindingCertificate
		s, ok := cert.PrivateKey.(crypto.Signer)
		if !ok {
			t.Fatal("the binding certificate's private key is not a signer")
		}
		return s
	}()

	// Drop the cache's reference, as a re-mint or an identity change would. The
	// caller's copy is now the only thing keeping the key alive.
	certCache.clear()

	// Make the returned *tls.Certificate collectable and give finalizers a
	// chance to run before the key is used.
	for i := 0; i < 3; i++ {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
	}

	digest := sha256.Sum256([]byte("payload signed from a by-value copy"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("signing from a by-value copy of the certificate failed: %v", err)
	}
}

func TestIMDSv2AlternatingCertificatesKeepTheirClients(t *testing.T) {
	// The cache is process-wide and bounded, so a test that inherits entries
	// from another test can see its own two clients evicted for reasons that
	// have nothing to do with what it is asserting.
	withCleanCaches(t)
	first := selfSignedTLSCertificate(t)
	second := selfSignedTLSCertificate(t)

	firstClient := mtlsHTTPClient(first)
	secondClient := mtlsHTTPClient(second)
	if firstClient == secondClient {
		t.Fatal("two certificates shared a client")
	}
	// Two identities in one process alternate. Dropping the previous client
	// every time the certificate changes would rebuild a transport on every
	// acquisition, which is the churn the cache exists to remove.
	if mtlsHTTPClient(first) != firstClient {
		t.Fatal("alternating certificates evicted each other's client")
	}
	if mtlsHTTPClient(second) != secondClient {
		t.Fatal("alternating certificates evicted each other's client")
	}
}

func TestIMDSv2MtlsClientCacheIsBounded(t *testing.T) {
	withCleanCaches(t)
	for i := 0; i < mtlsClientCacheLimit*3; i++ {
		mtlsHTTPClient(selfSignedTLSCertificate(t))
	}
	mtlsClientCache.mu.Lock()
	size := len(mtlsClientCache.clients)
	mtlsClientCache.mu.Unlock()
	if size > mtlsClientCacheLimit {
		t.Fatalf("cached clients = %d, want at most %d", size, mtlsClientCacheLimit)
	}
}

func selfSignedTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "mtls-client-cache-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return cert
}

// A metadata document with no attestationEndpoint is refused even when this
// acquisition is not going to attest.
//
// MSAL .NET rejects the document outright in CsrMetadata.ValidateCsrMetadata
// rather than only on the attesting path, so a host that omits the field is
// misconfigured for every caller and both libraries refuse it at the same
// point. TestIMDSv2RejectsHostileAttestationEndpoint covers the attesting side,
// but it cannot pin this: it asks for attestation, and attestationURL rejects an
// empty endpoint with a message carrying the same "no attestationEndpoint" text,
// so deleting the check in csrMetadata.validate leaves that test green. This one
// never asks for attestation, so only validate can produce the error.
func TestIMDSv2RejectsMetadataWithoutAttestationEndpointWhenNotAttesting(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.metadataBody = `{"cuId":{"vmId":"vm-1"},"clientId":"` + fake.clientID +
		`","tenantId":"` + fake.tenantID + `"}`
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("expected metadata without an attestationEndpoint to be rejected")
	}
	if !strings.Contains(err.Error(), "attestationEndpoint") {
		t.Errorf("error = %v, want it to name attestationEndpoint", err)
	}
	// The document is refused on leg 1, so no credential is ever requested.
	if got := fake.countCalls("issue"); got != 0 {
		t.Errorf("issue requests = %d, want 0", got)
	}
}

// Every field certificateRequestResponse.validate requires is refused when IMDS
// leaves it out. identity_type is the field that makes this worth pinning:
// nothing downstream reads it, so validate is the only thing standing between a
// truncated issuance response and a certificate the caller believes is complete.
func TestIMDSv2RejectsIncompleteCredentialResponse(t *testing.T) {
	for _, field := range []string{
		"client_id",
		"tenant_id",
		"certificate",
		"identity_type",
		"mtls_authentication_endpoint",
	} {
		t.Run(field, func(t *testing.T) {
			withCleanCaches(t)
			fake := newIMDSFake(t)
			fake.omitIssueFields = []string{field}
			client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

			ar, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
				WithMtlsProofOfPossession())
			if err == nil {
				t.Fatalf("expected a response missing %s to be rejected, got token %q", field, ar.AccessToken)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("error = %v, want it to name the missing field %s", err, field)
			}
			// A rejected issuance must not reach the token endpoint.
			if got := fake.countCalls("token"); got != 0 {
				t.Errorf("token requests = %d, want 0", got)
			}
		})
	}
}

// A 404 from the credential endpoint is a plain failure, not the signal that
// this host only speaks IMDSv1.
//
// Only leg 1 carries that meaning: reaching leg 2 at all proves the host served
// the v2 metadata document, so a 404 here is the endpoint misbehaving. Mapping
// it to ErrMtlsPoPNotSupportedInIMDSv1 would tell a credential chain to give up
// on managed identity for a host that plainly supports it.
func TestIMDSv2CredentialLegNotFoundIsNotAV1Signal(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.issueStatus = http.StatusNotFound
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("expected a 404 from the credential endpoint to fail the acquisition")
	}
	if errors.Is(err, ErrMtlsPoPNotSupportedInIMDSv1) {
		t.Errorf("error = %v, want a generic failure rather than the IMDSv1 signal", err)
	}
}

// A metadata document larger than the read limit is refused rather than buffered.
//
// The IMDS legs are unauthenticated plain HTTP, so anything answering on the
// link-local address can reply with as much data as it likes. readIMDSResponse
// caps the body at 1 MiB; without the cap a hostile responder could make the
// process allocate without bound.
//
// The body is a fully valid metadata document with a large ignored field in
// front of the real ones. That shape is what makes the test sensitive: the cap
// truncates it mid-padding into unparseable JSON, while a build without the cap
// would read the whole thing, find every required field, and mint a token. A
// body of padding alone would be rejected either way, for missing fields, and
// would prove nothing.
func TestIMDSv2RejectsAnOversizedMetadataBody(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.metadataBody = `{"padding":"` + strings.Repeat("a", 2<<20) + `","cuId":{"vmId":"vm-1"},"clientId":"` +
		fake.clientID + `","tenantId":"` + fake.tenantID + `","attestationEndpoint":"` +
		fake.attestationEndpoint + `"}`
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	ar, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession())
	if err == nil {
		t.Fatalf("expected an oversized metadata body to be rejected, got token %q", ar.AccessToken)
	}
	// The body never parses, so no credential is requested.
	if got := fake.countCalls("issue"); got != 0 {
		t.Errorf("issue requests = %d, want 0", got)
	}
}
