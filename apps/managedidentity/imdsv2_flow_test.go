// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/storage"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
)

// fakeKeyProvider hands out a software RSA key that reports itself as
// KeyGuard-protected. It exists so the protocol can be exercised on hosts
// without Virtualization-based Security; the real provider is covered
// separately by the KeyGuard tests, which only run where VBS is present.
type fakeKeyProvider struct {
	mu      sync.Mutex
	keys    map[string]*rsa.PrivateKey
	typ     keyType
	err     error
	creates int
}

func newFakeKeyProvider() *fakeKeyProvider {
	return &fakeKeyProvider{keys: map[string]*rsa.PrivateKey{}, typ: keyTypeKeyGuard}
}

func (f *fakeKeyProvider) getOrCreateKey(name string) (bindingKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return bindingKey{}, f.err
	}
	key, ok := f.keys[name]
	if !ok {
		var err error
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return bindingKey{}, err
		}
		f.keys[name] = key
		f.creates++
	}
	return bindingKey{Signer: key, Type: f.typ, Close: func() error { return nil }}, nil
}

func (f *fakeKeyProvider) deleteKey(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.keys, name)
	return nil
}

// rotate replaces the stored key without deleting the name, simulating a VBS
// container that was recreated underneath a cached certificate.
func (f *fakeKeyProvider) rotate(t *testing.T, name string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[name] = key
}

// imdsFake is a stand-in for the metadata service and the Entra token endpoint.
type imdsFake struct {
	t *testing.T

	metadataServer *httptest.Server
	tokenServer    *httptest.Server

	caCert *x509.Certificate
	caKey  *rsa.PrivateKey

	mu sync.Mutex
	// calls records every request path in order, so a test can assert exactly
	// how many round trips an acquisition needed.
	calls []string

	clientID string
	tenantID string

	// omitServerHeader and serverHeader control the anti-spoofing header.
	omitServerHeader bool
	serverHeader     string

	metadataStatus int
	computeBody    string
	redirectTo     string
	redirectStatus int
	issueStatus    int

	// issueFailures is the number of leading credential requests that fail with
	// a retriable status before one succeeds.
	issueFailures int

	// tokenFailures is the number of leading token requests that fail with
	// tokenFailureBody before one succeeds.
	tokenFailures    int
	tokenFailureCode int
	tokenFailureBody string

	// tokenType is what the token endpoint claims it issued.
	tokenType string
	// lastTokenForm is the form body of the most recent token request.
	lastTokenForm url.Values
	// sawClientCert records whether the token request presented a certificate.
	sawClientCert bool
	// presentedCert is the leaf the client presented on the last token request.
	presentedCert *x509.Certificate
	// lastAttestationToken is the attestation token carried by the most recent
	// issue request, so a test can tell an attested request from a plain one.
	lastAttestationToken string
	// certLifetime is how long an issued binding certificate is valid for. It is
	// settable so a test can drive the refresh window.
	certLifetime time.Duration
	// attestationEndpoint is what leg 1 advertises. It is settable so a test can
	// prove a hostile value is rejected.
	attestationEndpoint string
	// metadataBody, when set, replaces the leg 1 response body verbatim.
	metadataBody string
	// omitIssueFields names fields to drop from the leg 2 response, so a test
	// can prove an incomplete issuance is rejected.
	omitIssueFields []string
}

func newIMDSFake(t *testing.T) *imdsFake {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "imds-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	f := &imdsFake{
		t:              t,
		caCert:         ca,
		caKey:          caKey,
		clientID:       "8c8a1b0a-4d40-4d9e-9a4f-1f2a3b4c5d6e",
		tenantID:       "72f988bf-86f1-41af-91ab-2d7cd011db47",
		serverHeader:   "IMDS/150.870.65.2153",
		metadataStatus: http.StatusOK,
		issueStatus:    http.StatusOK,
		tokenType:      "mtls_pop",

		// Comfortably outside bindingCertRefreshWindow, so the default fixture
		// certificate is cacheable and reusable. A test that wants to drive the
		// refresh window sets this shorter.
		certLifetime:        30 * 24 * time.Hour,
		attestationEndpoint: "https://attestation.example",
	}

	f.metadataServer = httptest.NewServer(http.HandlerFunc(f.handleMetadata))
	// The token endpoint requests a client certificate but does not require a
	// verified chain, so a test can inspect what was presented while still
	// letting the handshake complete.
	f.tokenServer = httptest.NewUnstartedServer(http.HandlerFunc(f.handleToken))
	f.tokenServer.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	f.tokenServer.StartTLS()

	t.Cleanup(func() {
		f.metadataServer.Close()
		f.tokenServer.Close()
	})
	return f
}

func (f *imdsFake) record(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, path)
}

func (f *imdsFake) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// countOf reports how many times one endpoint was called, which is how a test
// distinguishes a cache hit from a re-issue without counting the round trips
// that happen either way.
func (f *imdsFake) countOf(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, call := range f.calls {
		if call == path {
			n++
		}
	}
	return n
}

func (f *imdsFake) resetCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

func (f *imdsFake) attestationToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastAttestationToken
}

func (f *imdsFake) writeServerHeader(w http.ResponseWriter) {
	if !f.omitServerHeader {
		w.Header().Set("Server", f.serverHeader)
	}
}

func (f *imdsFake) handleMetadata(w http.ResponseWriter, r *http.Request) {
	if f.redirectTo != "" {
		f.record("redirect")
		http.Redirect(w, r, f.redirectTo, f.redirectStatus)
		return
	}
	if strings.Contains(r.URL.Path, "issuecredential") {
		f.handleIssue(w, r)
		return
	}
	if strings.Contains(r.URL.Path, "/instance/compute") {
		f.handleCompute(w, r)
		return
	}
	// An IMDSv1 token request carries a resource but no cred-api-version.
	if r.URL.Query().Get("cred-api-version") == "" && r.URL.Query().Get("resource") != "" {
		f.record("v1token")
		f.writeServerHeader(w)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.record("metadata")
	f.writeServerHeader(w)
	if f.metadataStatus != http.StatusOK {
		w.WriteHeader(f.metadataStatus)
		_, _ = w.Write([]byte(`{"error":"identity_not_found","error_description":"no identity"}`))
		return
	}
	if r.Header.Get("Metadata") != "true" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("cred-api-version") != "2.0" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if f.metadataBody != "" {
		_, _ = w.Write([]byte(f.metadataBody))
		return
	}
	// Real IMDS omits vmssId entirely on a standalone VM rather than sending it
	// empty. The fixture matches a captured response: inventing a shape the
	// service never sends is what let a bad CUID attribute reach production.
	_ = json.NewEncoder(w).Encode(map[string]any{
		"cuId":                map[string]string{"vmId": "vm-1"},
		"clientId":            f.clientID,
		"tenantId":            f.tenantID,
		"attestationEndpoint": f.attestationEndpoint,
	})
}

// handleCompute serves the IMDSv1 instance compute document.
//
// It answers 404 by default. The document is only consulted when the v2 probe
// reports a v1-only host, so a test that wants a v1 binding strength says so by
// setting computeBody.
func (f *imdsFake) handleCompute(w http.ResponseWriter, r *http.Request) {
	f.record("compute")
	f.writeServerHeader(w)
	if r.Header.Get("Metadata") != "true" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get(apiVersionQueryParameterName) != imdsComputeAPIVersion {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if f.computeBody == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(f.computeBody))
}

func (f *imdsFake) handleIssue(w http.ResponseWriter, r *http.Request) {
	f.record("issue")
	f.writeServerHeader(w)
	// Live IMDS rejects a request that omits these, so the fake does too.
	// Without the check a mutation that drops setIMDSHeaders from
	// issueCredential leaves every test green.
	if r.Header.Get("Metadata") != "true" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad_request","error_description":"the Metadata header is required"}`))
		return
	}
	if r.Header.Get("x-ms-client-request-id") == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad_request","error_description":"a correlation ID is required"}`))
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	if r.URL.Query().Get("cred-api-version") != "2.0" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Two identities can now mint concurrently, so the fake's mutable state is
	// guarded. The lock is not held across signing so the handlers still
	// overlap, which is what the concurrency tests are asserting.
	f.mu.Lock()
	if f.issueFailures > 0 {
		f.issueFailures--
		f.mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	status := f.issueStatus
	f.mu.Unlock()
	if status != http.StatusOK {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"bad_request","error_description":"nope"}`))
		return
	}
	var body certificateRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.lastAttestationToken = body.AttestationToken
	f.mu.Unlock()
	der, err := base64.StdEncoding.DecodeString(body.CSR)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// The service would reject a CSR it cannot verify, so the fake does too:
	// this is what makes the test prove the key really signed the request.
	if err := csr.CheckSignature(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(f.certLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, leaf, f.caCert, csr.PublicKey, f.caKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	issued := map[string]string{
		"client_id":                    f.clientID,
		"tenant_id":                    f.tenantID,
		"certificate":                  base64.StdEncoding.EncodeToString(certDER),
		"identity_type":                "SAMI",
		"mtls_authentication_endpoint": f.tokenServer.Listener.Addr().String(),
	}
	for _, field := range f.omitIssueFields {
		delete(issued, field)
	}
	_ = json.NewEncoder(w).Encode(issued)
}

func (f *imdsFake) handleToken(w http.ResponseWriter, r *http.Request) {
	f.record("token")
	_ = r.ParseForm()

	// ESTS rejects a request missing any of these, so the fake does too.
	// Without the check a mutation that drops one of the form fields from
	// requestEntraToken leaves every test green.
	for _, required := range []string{"client_id", "grant_type", "scope"} {
		if r.Form.Get(required) == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"missing ` + required + `"}`))
			return
		}
	}
	if got := r.Form.Get("grant_type"); got != "client_credentials" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"unsupported_grant_type","error_description":"` + got + `"}`))
		return
	}

	f.mu.Lock()
	f.lastTokenForm = r.Form
	f.sawClientCert = r.TLS != nil && len(r.TLS.PeerCertificates) > 0
	if f.sawClientCert {
		f.presentedCert = r.TLS.PeerCertificates[0]
	}
	failuresLeft := f.tokenFailures
	if failuresLeft > 0 {
		f.tokenFailures--
	}
	f.mu.Unlock()

	if failuresLeft > 0 {
		code := f.tokenFailureCode
		if code == 0 {
			code = http.StatusUnauthorized
		}
		w.WriteHeader(code)
		body := f.tokenFailureBody
		if body == "" {
			body = `{"error":"invalid_client","error_description":"certificate rejected"}`
		}
		_, _ = w.Write([]byte(body))
		return
	}

	// ESTS answers with the type that was asked for, so the fake echoes it too.
	// A test that wants the service to answer with something other than what
	// was requested sets tokenType, which is how the bound-request-answered-with
	// -a-bearer-token case is driven.
	tokenType := f.tokenType
	if requested := r.Form.Get("token_type"); requested == "" || strings.EqualFold(requested, "bearer") {
		tokenType = "Bearer"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "test-access-token",
		"token_type":   tokenType,
		"expires_in":   3599,
		"client_id":    f.clientID,
	})
}

// newTestClient builds a managed identity client wired to the fake.
func (f *imdsFake) newTestClient(t *testing.T, id ID, provider keyProvider, opts ...ClientOption) Client {
	t.Helper()
	t.Setenv(identityEndpointEnvVar, "")
	t.Setenv(msiEndpointEnvVar, "")
	t.Setenv(identityHeaderEnvVar, "")
	t.Setenv(imdsEndVar, "")
	t.Setenv(msiSecretEnvVar, "")
	t.Setenv(identityServerThumbprintEnvVar, "")
	t.Setenv(azurePodIdentityAuthorityHostEnvVar, f.metadataServer.URL)

	client, err := New(id, append([]ClientOption{WithHTTPClient(f.metadataServer.Client())}, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	client.keyProvider = provider
	// The fake's TLS certificate is self-signed, so the token leg needs a
	// transport that trusts it. Everything else about the client is unchanged.
	client.mtlsClientFactory = func(cert tls.Certificate) *http.Client {
		pool := x509.NewCertPool()
		pool.AddCert(f.tokenServer.Certificate())
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
					RootCAs:      pool,
					MinVersion:   tls.VersionTLS12,
				},
			},
		}
	}
	return client
}

// withCleanCaches isolates a test from certificates and tokens another test
// cached, since both caches are process-wide.
func withCleanCaches(t *testing.T) *fakePersistentCertCache {
	t.Helper()
	certCache.clear()
	clearAttestationCache()
	clearMtlsClientCache()
	clearCapabilitiesCache()
	cacheManager = storage.New(nil)
	platformSupportsMtlsPoP = func() bool { return true }
	// The real persistent cache is the user's own certificate store. A test
	// must not write to it, and must not read a certificate an earlier run left
	// in it, so it is replaced for the duration.
	persisted := newFakePersistentCertCache()
	realPersisted := swapPersistentCache(persisted)
	// The retry schedule is real time. Tests that exercise a retriable status
	// would otherwise wait out the backoff, so the wait is recorded rather than
	// served. A test that cares about the schedule installs its own.
	realWait := retryWait
	retryWait = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	t.Cleanup(func() {
		certCache.clear()
		clearAttestationCache()
		clearMtlsClientCache()
		clearCapabilitiesCache()
		cacheManager = storage.New(nil)
		platformSupportsMtlsPoP = func() bool { return runtime.GOOS == "windows" }
		retryWait = realWait
		swapPersistentCache(realPersisted)
	})
	return persisted
}

// withStubAttestation substitutes the attestation provider so a test can drive
// the attested path on a host that has neither KeyGuard nor the native library.
// It returns a pointer to the call count so a test can assert that attestation
// was, or was not, attempted at all.
func withStubAttestation(t *testing.T, token string, err error) *int {
	t.Helper()
	calls := 0
	original := attestKeyGuardFn
	attestKeyGuardFn = func(endpoint, clientID string, key bindingKey) (string, error) {
		calls++
		return token, err
	}
	t.Cleanup(func() { attestKeyGuardFn = original })
	return &calls
}

func TestIMDSv2SendsNoAttestationTokenWithoutOptIn(t *testing.T) {
	withCleanCaches(t)
	calls := withStubAttestation(t, "stub-attestation-jwt", nil)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if *calls != 0 {
		t.Fatalf("attestation was attempted %d times without WithAttestationSupport", *calls)
	}
	if fake.attestationToken() != "" {
		t.Fatalf("attestation token = %q, want empty", fake.attestationToken())
	}
}

func TestIMDSv2SendsAttestationTokenWhenOptedIn(t *testing.T) {
	withCleanCaches(t)
	calls := withStubAttestation(t, "stub-attestation-jwt", nil)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("attestation attempted %d times, want 1", *calls)
	}
	if fake.attestationToken() != "stub-attestation-jwt" {
		t.Fatalf("attestation token = %q, want stub-attestation-jwt", fake.attestationToken())
	}
}

// A caller that asked for attestation is never quietly downgraded: failing to
// attest has to surface rather than produce a credential without the guarantee
// the caller requested.
func TestIMDSv2FailsWhenAttestationUnavailable(t *testing.T) {
	withCleanCaches(t)
	withStubAttestation(t, "", ErrAttestationUnavailable)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession(), WithAttestationSupport())
	if err == nil {
		t.Fatal("AcquireToken succeeded, so the caller was silently given a non-attested credential")
	}
	if !errors.Is(err, ErrAttestationUnavailable) {
		t.Fatalf("error = %v, want it to wrap ErrAttestationUnavailable", err)
	}
	for _, call := range fake.calls {
		if call == "issue" {
			t.Fatal("a credential request was sent even though attestation failed")
		}
	}
}

// An attested certificate and a plain one are different credentials, so they
// must not share a cache entry in either direction. MSAL .NET separates them
// with an #att tag on the certificate cache key for the same reason.
func TestIMDSv2AttestedAndNonAttestedCertificatesDoNotShareCache(t *testing.T) {
	bound := []AcquireTokenOption{WithMtlsProofOfPossession()}
	attested := []AcquireTokenOption{WithMtlsProofOfPossession(), WithAttestationSupport()}
	for _, tc := range []struct {
		name       string
		first      []AcquireTokenOption
		second     []AcquireTokenOption
		wantSecond string
	}{
		{name: "attested cannot be reused by a plain request", first: attested, second: bound, wantSecond: ""},
		{name: "plain cannot be reused by an attested request", first: bound, second: attested, wantSecond: "stub-attestation-jwt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withCleanCaches(t)
			withStubAttestation(t, "stub-attestation-jwt", nil)
			fake := newIMDSFake(t)
			client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

			if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", tc.first...); err != nil {
				t.Fatalf("first AcquireToken: %v", err)
			}
			// A different resource misses the token cache, so the certificate
			// cache alone decides whether a new certificate is issued.
			fake.resetCalls()
			if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", tc.second...); err != nil {
				t.Fatalf("second AcquireToken: %v", err)
			}
			issued := false
			for _, call := range fake.calls {
				if call == "issue" {
					issued = true
				}
			}
			if !issued {
				t.Fatal("the second request reused the first certificate, so attested and non-attested credentials shared a cache entry")
			}
			if fake.attestationToken() != tc.wantSecond {
				t.Fatalf("attestation token on the second request = %q, want %q", fake.attestationToken(), tc.wantSecond)
			}
		})
	}
}

// stubAttestationJWT builds a token shaped like an MAA statement, carrying the
// expiry the cache reads. The signature is not verified anywhere in this flow,
// so an unsigned third segment is enough.
func stubAttestationJWT(t *testing.T, exp time.Time) string {
	t.Helper()
	enc := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := enc(map[string]string{"alg": "none", "typ": "JWT"})
	payload := enc(map[string]any{"exp": exp.Unix(), "iss": "https://maa.test"})
	return header + "." + payload + ".stub-signature"
}

// withCountedAttestation substitutes the attestation provider with one that
// returns whatever tokenFor produces and counts how often it is reached, which
// is what makes a cache hit observable.
func withCountedAttestation(t *testing.T, tokenFor func() string) *int {
	t.Helper()
	calls := 0
	original := attestKeyGuardFn
	attestKeyGuardFn = func(endpoint, clientID string, key bindingKey) (string, error) {
		calls++
		return tokenFor(), nil
	}
	t.Cleanup(func() { attestKeyGuardFn = original })
	return &calls
}

// The scope sent on leg 3 has to match what MSAL .NET sends for the same
// resource, since the two libraries acquire tokens for the same resources from
// the same endpoint.
//
// .NET's public entry point documents the resource as "{ResourceIdUri}" or
// "{ResourceIdUri/.default}"
// (IManagedIdentityApplication.AcquireTokenForManagedIdentity) and normalizes
// it in two steps: ScopeHelper.RemoveDefaultSuffixIfPresent at the API
// boundary, then resource.TrimEnd('/') + "/.default" when it builds the request
// (ManagedIdentityAuthRequest). netScopeForResource reproduces both, so this
// compares the two libraries rather than restating what Go already does.
func TestScopeForResourceMatchesDotNet(t *testing.T) {
	netScopeForResource := func(resource string) string {
		const suffix = "/.default"
		if strings.HasSuffix(resource, suffix) {
			resource = resource[:strings.LastIndex(resource, suffix)]
		}
		return strings.TrimRight(resource, "/") + suffix
	}
	for _, resource := range []string{
		"https://vault.azure.net",
		"https://vault.azure.net/",
		"https://vault.azure.net//",
		"https://vault.azure.net/.default",
		"https://vault.azure.net/.default/",
		"https://graph.microsoft.com/.default",
		"https://management.azure.com",
		"api://00000000-0000-0000-0000-000000000000",
		"api://00000000-0000-0000-0000-000000000000/.default",
		"https://host/path",
		"https://host/path/.default",
		"https://vault.azure.net/.Default",
	} {
		// AcquireToken strips the suffix at the API boundary, which is exactly
		// where .NET's builder strips it, so the comparison starts there.
		got := scopeForResource(strings.TrimSuffix(resource, "/.default"))
		if want := netScopeForResource(resource); got != want {
			t.Errorf("scope for %q = %q, .NET sends %q", resource, got, want)
		}
	}
}

// Concurrent misses for one key collapse into a single attestation. The native
// call and the MAA round trip behind it are expensive and MAA is rate-limited,
// so N simultaneous callers must not become N attestations. MSAL .NET pins the
// same behaviour with
// MaaTokenCache_ConcurrentCacheMiss_SingleFlightCallsProviderOnce.
func TestAttestationCollapsesConcurrentMisses(t *testing.T) {
	clearAttestationCache()
	t.Cleanup(clearAttestationCache)

	signer, err := rsa.GenerateKey(rand.Reader, csrKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	key := bindingKey{Signer: signer, Type: keyTypeKeyGuard}
	token := stubAttestationJWT(t, time.Now().Add(time.Hour))

	var calls int32
	release := make(chan struct{})
	original := attestKeyGuardFn
	attestKeyGuardFn = func(endpoint, clientID string, k bindingKey) (string, error) {
		// Only the first caller holds the door open. A caller that was not
		// collapsed arrives here while it is held and is counted.
		if atomic.AddInt32(&calls, 1) == 1 {
			<-release
		}
		return token, nil
	}
	t.Cleanup(func() { attestKeyGuardFn = original })

	const callers = 8
	ready := make(chan struct{}, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	got := make([]string, callers)
	errs := make([]error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			got[i], errs[i] = attestKeyGuardCached(
				context.Background(), "https://attestation.example", "client", key)
		}(i)
	}
	for i := 0; i < callers; i++ {
		<-ready
	}
	close(start)

	// Every caller is now runnable and unblocked, so an implementation without
	// the gate reaches the provider immediately. The wait only has to outlast
	// that, not synchronise with it.
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("attestations = %d, want 1: concurrent misses were not collapsed", n)
	}
	for i := range got {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if got[i] != token {
			t.Errorf("caller %d = %q, want the attested statement", i, got[i])
		}
	}
}

// Two identities on the same host share one binding key, so MAA has already
// vouched for the key by the time the second certificate is minted.
func TestIMDSv2ReusesAttestationTokenForTheSameKey(t *testing.T) {
	withCleanCaches(t)
	token := stubAttestationJWT(t, time.Now().Add(time.Hour))
	calls := withCountedAttestation(t, func() string { return token })
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	system := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := system.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("system-assigned AcquireToken: %v", err)
	}
	user := fake.newTestClient(t, UserAssignedClientID("11111111-2222-3333-4444-555555555555"), provider)
	if _, err := user.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("user-assigned AcquireToken: %v", err)
	}

	if provider.creates != 1 {
		t.Fatalf("created %d keys, want 1: the test needs both identities to share a binding key", provider.creates)
	}
	if *calls != 1 {
		t.Fatalf("attested %d times, want 1: the second certificate should have reused the cached statement", *calls)
	}
	if fake.attestationToken() != token {
		t.Fatalf("the second request sent %q, want the cached statement", fake.attestationToken())
	}
}

// A statement close enough to its expiry could lapse before the service reads
// it, so the cache stops serving it before it actually expires.
func TestIMDSv2ReattestsWhenTheAttestationTokenNearsExpiry(t *testing.T) {
	persisted := withCleanCaches(t)
	realNow := now
	base := realNow()
	current := base
	now = func() time.Time { return current }
	t.Cleanup(func() { now = realNow })

	calls := withCountedAttestation(t, func() string { return stubAttestationJWT(t, base.Add(10*time.Minute)) })
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("attested %d times on the first acquisition, want 1", *calls)
	}

	// Six minutes on, the statement has four minutes left, which is inside the
	// five-minute buffer.
	current = base.Add(6 * time.Minute)
	certCache.clear()
	persisted.reset()
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if *calls != 2 {
		t.Fatalf("attested %d times, want 2: a statement inside the expiry buffer should not be served", *calls)
	}
}

// A statement vouches for one key. If the key behind a container is replaced,
// the cached statement describes a key that is no longer in use and must not be
// sent with a request carrying the new one.
func TestIMDSv2ReattestsWhenTheBindingKeyChanges(t *testing.T) {
	withCleanCaches(t)
	calls := withCountedAttestation(t, func() string { return stubAttestationJWT(t, time.Now().Add(time.Hour)) })
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}

	// The container keeps its name while the key inside it changes, which is
	// what a name-based cache key would fail to notice.
	provider.rotate(t, bindingKeyName)
	certCache.clear()
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if *calls != 2 {
		t.Fatalf("attested %d times, want 2: the statement for the replaced key should not have been reused", *calls)
	}
}

// A statement with no readable lifetime is still usable, but there is no basis
// for deciding when to stop trusting it, so it is not stored.
func TestIMDSv2DoesNotCacheAttestationTokenWithoutExpiry(t *testing.T) {
	persisted := withCleanCaches(t)
	calls := withCountedAttestation(t, func() string { return "not-a-jwt" })
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	if fake.attestationToken() != "not-a-jwt" {
		t.Fatalf("attestation token = %q, want it sent even though it is not cacheable", fake.attestationToken())
	}
	certCache.clear()
	persisted.reset()
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if *calls != 2 {
		t.Fatalf("attested %d times, want 2: a token with no readable expiry should not be cached", *calls)
	}
}

// The endpoint belongs in the cache key because MAA instances issue their own
// statements: one region's token is not valid at another. Trailing slashes and
// casing are incidental to that identity, so they are normalized away.
func TestAttestationCacheKeySeparatesEndpoints(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	bound := bindingKey{Signer: key, Type: keyTypeKeyGuard}

	keyFor := func(endpoint string, bk bindingKey) string {
		t.Helper()
		got, err := attestationCacheKey(endpoint, bk)
		if err != nil {
			t.Fatalf("attestationCacheKey(%q): %v", endpoint, err)
		}
		return got
	}

	eastus := keyFor("https://eastus.attest.azure.net", bound)
	if got := keyFor("https://EastUS.attest.azure.net/", bound); got != eastus {
		t.Errorf("trailing slash and casing changed the key:\n got %q\nwant %q", got, eastus)
	}
	if got := keyFor("https://westus.attest.azure.net", bound); got == eastus {
		t.Error("two regions produced the same key, so a statement could be reused at an endpoint that did not issue it")
	}
	if got := keyFor("https://eastus.attest.azure.net", bindingKey{Signer: other, Type: keyTypeKeyGuard}); got == eastus {
		t.Error("two keys produced the same cache key, so a statement could vouch for the wrong key")
	}
	if _, err := attestationCacheKey("https://eastus.attest.azure.net", bindingKey{}); err == nil {
		t.Error("a binding key with no signer should not produce a cache key")
	}
}

func TestIMDSv2AcquiresBoundTokenInThreeCalls(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	client := fake.newTestClient(t, SystemAssigned(), provider)

	res, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if res.AccessToken != "test-access-token" {
		t.Fatalf("access token = %q", res.AccessToken)
	}
	if got := fake.calls; len(got) != 3 || got[0] != "metadata" || got[1] != "issue" || got[2] != "token" {
		t.Fatalf("call sequence = %v, want [metadata issue token]", got)
	}
	if !fake.sawClientCert {
		t.Fatal("the token request did not present a client certificate")
	}
	if res.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("token type = %q, want mtls_pop", res.Metadata.TokenType)
	}
	if res.BindingCertificate == nil {
		t.Fatal("BindingCertificate is nil, so the caller cannot call the resource")
	}
	// The certificate handed to the caller must be the one the service saw,
	// otherwise the bound token would be rejected at the resource.
	if !fake.presentedCert.Equal(res.BindingCertificate.Leaf) {
		t.Fatal("BindingCertificate is not the certificate presented on the handshake")
	}
	if got := fake.lastTokenForm.Get("token_type"); got != "mtls_pop" {
		t.Fatalf("token_type form value = %q, want mtls_pop", got)
	}
	if got := fake.lastTokenForm.Get("scope"); got != "https://vault.azure.net/.default" {
		t.Fatalf("scope = %q", got)
	}
	if got := fake.lastTokenForm.Get("grant_type"); got != "client_credentials" {
		t.Fatalf("grant_type = %q", got)
	}
}

func TestIMDSv2ReusesCachedCertificate(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	client := fake.newTestClient(t, SystemAssigned(), provider)

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	// A different resource forces a token cache miss while leaving the
	// certificate cache populated.
	fake.resetCalls()
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if got := fake.calls; len(got) != 2 || got[0] != "metadata" || got[1] != "token" {
		t.Fatalf("call sequence = %v, want [metadata token]: the certificate should have been reused", got)
	}
	if provider.creates != 1 {
		t.Fatalf("created %d keys, want 1", provider.creates)
	}
}

func TestIMDSv2ServesTokenFromCacheWithoutNetwork(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	fake.resetCalls()
	res, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if fake.callCount() != 0 {
		t.Fatalf("expected no network calls on a cache hit, got %v", fake.calls)
	}
	if res.Metadata.TokenSource != base.TokenSourceCache {
		t.Fatalf("token source = %v, want the cache", res.Metadata.TokenSource)
	}
	if res.AccessToken != "test-access-token" {
		t.Fatalf("access token = %q", res.AccessToken)
	}
	// A cached bound token is only usable alongside the certificate it is bound
	// to, so serving one without the certificate produces a token every
	// resource rejects. This is invisible to an acquisition-only assertion,
	// which is why it is checked on the cache-hit path specifically.
	if res.BindingCertificate == nil {
		t.Fatal("the cached bound token carries no binding certificate, so the caller cannot call the resource")
	}
	if !fake.presentedCert.Equal(res.BindingCertificate.Leaf) {
		t.Fatal("the cached token's binding certificate is not the one the token is bound to")
	}
	if res.BindingCertificateThumbprint() == "" {
		t.Fatal("the cached token's binding certificate has no thumbprint")
	}
	if len(res.BindingCertificate.Certificate) == 0 || res.BindingCertificate.PrivateKey == nil {
		t.Fatal("the cached token's binding certificate cannot be used for a handshake")
	}
}

func TestIMDSv2BoundAndBearerTokensDoNotShareCache(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	bound, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("bound AcquireToken: %v", err)
	}
	if bound.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("bound token type = %q", bound.Metadata.TokenType)
	}

	// The bearer request must not be satisfied by the bound token already in
	// the cache: it is only valid on a connection using the binding
	// certificate, so returning it here would produce a token the caller
	// cannot use.
	fake.resetCalls()
	bearer, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithRequestOverMtls())
	if err != nil {
		t.Fatalf("bearer AcquireToken: %v", err)
	}
	if bearer.Metadata.TokenType == "mtls_pop" {
		t.Fatal("a bearer request was served the certificate-bound token")
	}
	if fake.callCount() == 0 {
		t.Fatal("the bearer request was served from the bound token's cache entry")
	}
	// MSAL .NET asks for the type explicitly on this path rather than letting
	// ESTS default it, so the request carries token_type=bearer.
	if got := fake.lastTokenForm.Get("token_type"); got != "bearer" {
		t.Fatalf("a bearer request sent token_type=%q, want %q", got, "bearer")
	}
	if !fake.sawClientCert {
		t.Fatal("WithRequestOverMtls did not use a client certificate")
	}
}

func TestIMDSv2RejectsMissingServerHeader(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.omitServerHeader = true
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("expected an error when the responder did not identify itself as IMDS")
	}
	if fake.callCount() != 1 {
		t.Fatalf("the flow continued past the header check: %v", fake.calls)
	}
}

func TestIMDSv2RejectsForeignServerHeader(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.serverHeader = "nginx/1.25.0"
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err == nil {
		t.Fatal("expected an error when another server answered the metadata address")
	}
}

func TestIMDSv2ReportsV1OnlyHost(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.metadataStatus = http.StatusNotFound
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if !errors.Is(err, ErrMtlsPoPNotSupportedInIMDSv1) {
		t.Fatalf("error = %v, want ErrMtlsPoPNotSupportedInIMDSv1", err)
	}
}

// A 404 is the answer that decides IMDSv2 is unavailable on this host, so it is
// only believed once the retries are exhausted. An agent that is still starting
// can answer 404 briefly, and treating that as a permanent capability answer
// would fall back to IMDSv1 for the life of the process.
func TestIMDSv2RetriesA404BeforeReportingAV1OnlyHost(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.metadataStatus = http.StatusNotFound
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if !errors.Is(err, ErrMtlsPoPNotSupportedInIMDSv1) {
		t.Fatalf("error = %v, want ErrMtlsPoPNotSupportedInIMDSv1", err)
	}
	if got := strings.Join(fake.calls, ","); got != "metadata,metadata,metadata,metadata" {
		t.Errorf("calls = %q, want the 404 retried three times before it is believed", got)
	}
}

// The retry policy is wired to the client option rather than always on.
func TestIMDSv2HonorsWithRetryPolicyDisabled(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.metadataStatus = http.StatusNotFound
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider(), WithRetryPolicyDisabled())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if !errors.Is(err, ErrMtlsPoPNotSupportedInIMDSv1) {
		t.Fatalf("error = %v, want ErrMtlsPoPNotSupportedInIMDSv1", err)
	}
	if got := strings.Join(fake.calls, ","); got != "metadata" {
		t.Errorf("calls = %q, want a single attempt when the retry policy is disabled", got)
	}
}

// A transient failure on the credential leg is retried, and the retried POST
// still carries a usable CSR: the fake would fail to parse an empty body.
func TestIMDSv2RetriesTheCredentialLeg(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.issueFailures = 2
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if got := strings.Join(fake.calls, ","); got != "metadata,issue,issue,issue,token" {
		t.Errorf("calls = %q, want the credential request retried twice and then succeed", got)
	}
}

func TestIMDSv2RemintsCertificateOnInvalidClient(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	client := fake.newTestClient(t, SystemAssigned(), provider)

	// The first token request fails the way Entra reports a certificate it will
	// no longer accept.
	fake.tokenFailures = 1
	res, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if res.AccessToken != "test-access-token" {
		t.Fatalf("access token = %q", res.AccessToken)
	}
	// metadata, issue, token(fail), metadata, issue, token(ok)
	if got := strings.Join(fake.calls, ","); got != "metadata,issue,token,metadata,issue,token" {
		t.Fatalf("call sequence = %v, want a single re-mint and retry", fake.calls)
	}
}

// A server error from the token endpoint is retried on the certificate already
// in hand. It is distinct from the re-mint path, which reacts to a certificate
// Entra has rejected: a 503 says nothing about the certificate, so minting a
// new one would be wasted work against a service that is already struggling.
func TestIMDSv2RetriesTheTokenLegOnAServerError(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	fake.tokenFailures = 1
	fake.tokenFailureCode = http.StatusServiceUnavailable
	fake.tokenFailureBody = `{"error":"temporarily_unavailable"}`

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if got := strings.Join(fake.calls, ","); got != "metadata,issue,token,token" {
		t.Errorf("calls = %q, want the token request retried without a new certificate", got)
	}
}

func TestIMDSv2RetriesOnlyOnce(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	fake.tokenFailures = 5
	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("expected the second failure to surface rather than retry forever")
	}
	tokenCalls := 0
	for _, c := range fake.calls {
		if c == "token" {
			tokenCalls++
		}
	}
	if tokenCalls != 2 {
		t.Fatalf("made %d token requests, want exactly 2", tokenCalls)
	}
}

func TestIMDSv2DoesNotRetryOnUnrelatedFailure(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	// invalid_scope is a request problem. Minting a new certificate cannot fix
	// it, so retrying would only double the load on a rate-limited service.
	fake.tokenFailures = 1
	fake.tokenFailureCode = http.StatusBadRequest
	fake.tokenFailureBody = `{"error":"invalid_scope","error_description":"bad scope"}`

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err == nil {
		t.Fatal("expected the error to surface")
	}
	tokenCalls := 0
	for _, c := range fake.calls {
		if c == "token" {
			tokenCalls++
		}
	}
	if tokenCalls != 1 {
		t.Fatalf("made %d token requests, want 1: an unrelated failure must not re-mint", tokenCalls)
	}
}

func TestIMDSv2RejectsBearerTokenForBoundRequest(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	// The service answers a bound-token request with a bearer token, which is
	// what happens when the tenant has not enabled bound tokens.
	fake.tokenType = "Bearer"
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("a bearer token was accepted for a request that asked for a bound token")
	}
	if !strings.Contains(err.Error(), "bound") {
		t.Fatalf("error = %v, want it to explain the token was not bound", err)
	}
}

func TestIMDSv2DetectsOrphanedCertificate(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	client := fake.newTestClient(t, SystemAssigned(), provider)

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	// Simulate the isolated container being recreated: the cached certificate
	// still parses, but its private key no longer exists.
	provider.rotate(t, bindingKeyName)

	fake.resetCalls()
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if got := strings.Join(fake.calls, ","); got != "metadata,issue,token" {
		t.Fatalf("call sequence = %v, want the orphaned certificate to be reissued", fake.calls)
	}
}

func TestIMDSv2RejectsIdentityReassignment(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	// The VM's identity changed. The cached certificate names the old identity
	// and must not be reused.
	fake.clientID = "11111111-2222-3333-4444-555555555555"

	fake.resetCalls()
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if got := strings.Join(fake.calls, ","); got != "metadata,issue,token" {
		t.Fatalf("call sequence = %v, want a new certificate after the identity changed", fake.calls)
	}
}

func TestIMDSv2OptionsAreMutuallyExclusive(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithRequestOverMtls())
	if !errors.Is(err, ErrMtlsPoPAndBearerExclusive) {
		t.Fatalf("error = %v, want ErrMtlsPoPAndBearerExclusive", err)
	}
	if fake.callCount() != 0 {
		t.Fatal("an invalid option combination reached the network")
	}
}

func TestIMDSv2RequiresKeyGuard(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	// A software key must not be accepted: it would produce a token that looks
	// bound but offers none of the guarantees.
	provider.typ = keyTypeSoftware
	client := fake.newTestClient(t, SystemAssigned(), provider)

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if !errors.Is(err, ErrCredentialGuardNotAvailable) {
		t.Fatalf("error = %v, want ErrCredentialGuardNotAvailable", err)
	}
}

func TestIMDSv2RejectsUnsupportedPlatform(t *testing.T) {
	withCleanCaches(t)
	platformSupportsMtlsPoP = func() bool { return false }
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if !errors.Is(err, ErrMtlsNotSupportedForPlatform) {
		t.Fatalf("error = %v, want ErrMtlsNotSupportedForPlatform", err)
	}
	if fake.callCount() != 0 {
		t.Fatal("an unsupported platform still contacted the metadata service")
	}
}

func TestIMDSv2PlainAcquisitionIsUnaffected(t *testing.T) {
	withCleanCaches(t)

	// The v1 endpoint is not redirectable by environment variable, so the
	// request is intercepted at the transport instead. Recording it is what
	// makes this test meaningful: asserting only that the v2 legs were skipped
	// would also pass if the acquisition failed outright.
	var requested []string
	client, err := New(SystemAssigned(), WithHTTPClient(&http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			requested = append(requested, r.URL.String())
			body := `{"access_token":"v1-access-token","token_type":"Bearer","expires_on":"` +
				strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) +
				`","resource":"https://vault.azure.net","client_id":"c"}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    r,
			}, nil
		}),
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, err := client.AcquireToken(context.Background(), "https://vault.azure.net")
	if err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if result.AccessToken != "v1-access-token" {
		t.Fatalf("access token = %q, want the IMDSv1 token", result.AccessToken)
	}
	if result.BindingCertificate != nil {
		t.Fatal("a plain acquisition returned a binding certificate")
	}
	if len(requested) != 1 {
		t.Fatalf("requests = %v, want exactly one IMDSv1 token request", requested)
	}
	if !strings.Contains(requested[0], "api-version=2018-02-01") {
		t.Fatalf("request = %q, want the IMDSv1 token endpoint", requested[0])
	}
	for _, url := range requested {
		if strings.Contains(url, "cred-api-version") || strings.Contains(url, "issuecredential") {
			t.Fatalf("a plain acquisition used an IMDSv2 endpoint: %s", url)
		}
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestIMDSv2SendsRequiredHeaders(t *testing.T) {
	withCleanCaches(t)
	var metadataHeader, correlation, clientRequest string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadataHeader = r.Header.Get("Metadata")
		correlation = r.Header.Get("X-Ms-Correlation-Id")
		clientRequest = r.Header.Get("x-ms-client-request-id")
		w.Header().Set("Server", "IMDS/1.0")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	v := imdsV2{httpClient: srv.Client(), keyProvider: newFakeKeyProvider(), miType: SystemAssigned(), baseEndpoint: srv.URL}
	_, _ = v.getCsrMetadata(context.Background(), "corr-1")

	if metadataHeader != "true" {
		t.Errorf("Metadata header = %q, want true", metadataHeader)
	}
	if correlation != "corr-1" {
		t.Errorf("X-Ms-Correlation-Id = %q", correlation)
	}
	// Live IMDS rejects a request without this header, so it must be sent even
	// though it duplicates the correlation identifier.
	if clientRequest != "corr-1" {
		t.Errorf("x-ms-client-request-id = %q, want it to be sent", clientRequest)
	}
}

func TestIMDSv2UserAssignedIdentitySelectors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		id    ID
		param string
		value string
	}{
		{"client", UserAssignedClientID("cid"), "client_id", "cid"},
		{"object", UserAssignedObjectID("oid"), "object_id", "oid"},
		{"resource", UserAssignedResourceID("/subscriptions/x"), "mi_res_id", "/subscriptions/x"},
		{"system", SystemAssigned(), "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := imdsV2{miType: tc.id, baseEndpoint: "http://169.254.169.254"}
			got, err := v.endpoint(imdsV2CsrMetadataPath)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := url.Parse(got)
			if err != nil {
				t.Fatal(err)
			}
			u := parsed.Query()
			if u.Get("cred-api-version") != "2.0" {
				t.Errorf("cred-api-version = %q", u.Get("cred-api-version"))
			}
			if tc.param == "" {
				for _, k := range []string{"client_id", "object_id", "mi_res_id"} {
					if u.Get(k) != "" {
						t.Errorf("system assigned identity sent %s=%q", k, u.Get(k))
					}
				}
				return
			}
			if u.Get(tc.param) != tc.value {
				t.Errorf("%s = %q, want %q", tc.param, u.Get(tc.param), tc.value)
			}
		})
	}
}

func TestIMDSv2RejectsNonHTTPSTokenEndpoint(t *testing.T) {
	for _, endpoint := range []string{"http://evil.example", "ftp://evil.example", "://"} {
		b := &bindingCertificate{Endpoint: endpoint, TenantID: "t"}
		if _, err := b.tokenEndpoint(); err == nil {
			t.Errorf("endpoint %q was accepted", endpoint)
		}
	}
	// A bare host is the shape IMDS actually returns and must be accepted.
	b := &bindingCertificate{Endpoint: "mtlsauth.microsoft.com", TenantID: "tid"}
	got, err := b.tokenEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://mtlsauth.microsoft.com/tid/oauth2/v2.0/token" {
		t.Fatalf("token endpoint = %q", got)
	}
}

// The token endpoint is subject to the same parser differential as the
// attestation endpoint: the string is parsed again by net/http when it dials,
// so a value net/url and another parser read differently is one IMDS chooses
// the meaning of. Whatever survives validation must be the bare origin that was
// validated, and nothing that resolves elsewhere may survive at all.
func TestIMDSv2RejectsAmbiguousTokenEndpointAuthority(t *testing.T) {
	for _, test := range []struct {
		name     string
		endpoint string
		// want is the URL the token leg must use, or empty when the endpoint
		// has to be rejected.
		want string
	}{
		{"backslash authority", `https:/\/\attacker.example`, ""},
		{"single backslash", `https:/\attacker.example`, ""},
		{"backslash after host", `https://mtlsauth.microsoft.com\@attacker.example`, ""},
		{"userinfo host takeover", "https://mtlsauth.microsoft.com@attacker.example", ""},
		{"no host", "https://", ""},
		{"path is dropped", "https://mtlsauth.microsoft.com/../attacker.example", "https://mtlsauth.microsoft.com/tid/oauth2/v2.0/token"},
		{"query is dropped", "https://mtlsauth.microsoft.com/?next=attacker.example", "https://mtlsauth.microsoft.com/tid/oauth2/v2.0/token"},
		{"fragment is dropped", "https://mtlsauth.microsoft.com/#attacker.example", "https://mtlsauth.microsoft.com/tid/oauth2/v2.0/token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := &bindingCertificate{Endpoint: test.endpoint, TenantID: "tid"}
			got, err := b.tokenEndpoint()
			if test.want == "" {
				if err == nil {
					t.Fatalf("endpoint %q was accepted as %q", test.endpoint, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("tokenEndpoint(): %v", err)
			}
			if got != test.want {
				t.Fatalf("token endpoint = %q, want %q", got, test.want)
			}
		})
	}
}

// A redirect on an IMDS leg is refused rather than followed.
//
// Go's default policy follows up to ten redirects, so nothing about this is
// automatic. It matters because a 307 or 308 replays the request body, and on
// the /issuecredential leg that body carries the CSR and the attestation
// statement; a redirect on the token leg would present the binding certificate
// to whatever host the redirect names. The https-only guarantee the endpoint
// validation provides is worth nothing if the connection is then handed
// somewhere else.
func TestIMDSv2RefusesToFollowRedirects(t *testing.T) {
	var reached int32
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&reached, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(attacker.Close)

	for _, status := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			atomic.StoreInt32(&reached, 0)
			withCleanCaches(t)
			fake := newIMDSFake(t)
			fake.redirectTo = attacker.URL
			fake.redirectStatus = status
			client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

			_, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
				WithMtlsProofOfPossession())
			if err == nil {
				t.Fatal("AcquireToken succeeded through a redirect")
			}
			if !strings.Contains(err.Error(), "refusing to follow") {
				t.Fatalf("error = %v, want the redirect refusal", err)
			}
			if n := atomic.LoadInt32(&reached); n != 0 {
				t.Fatalf("the redirect target was reached %d times, and must never be reached", n)
			}
		})
	}
}

// A caller who set CheckRedirect has stated a policy, and MSAL does not
// silently replace explicit caller configuration. A client that is not an
// *http.Client cannot be guarded at all and is passed through unchanged rather
// than dropped.
func TestIMDSRedirectGuardLeavesACallersPolicyAlone(t *testing.T) {
	stated := func(*http.Request, []*http.Request) error { return nil }
	caller := &http.Client{CheckRedirect: stated}
	if got := imdsRedirectGuarded(caller); got != ops.HTTPClient(caller) {
		t.Fatal("a caller's own redirect policy was replaced")
	}

	plain := &http.Client{}
	guarded, ok := imdsRedirectGuarded(plain).(*http.Client)
	if !ok {
		t.Fatal("guarding an *http.Client did not return an *http.Client")
	}
	if guarded == plain {
		t.Fatal("the caller's own client was mutated rather than copied")
	}
	if guarded.CheckRedirect == nil {
		t.Fatal("no redirect policy was installed")
	}
	if plain.CheckRedirect != nil {
		t.Fatal("the caller's client was given a policy it did not ask for")
	}

	other := notAnHTTPClient{}
	if got := imdsRedirectGuarded(other); got != ops.HTTPClient(other) {
		t.Fatal("a client that is not an *http.Client was not passed through")
	}
}

type notAnHTTPClient struct{}

func (notAnHTTPClient) Do(*http.Request) (*http.Response, error) { return nil, nil }
func (notAnHTTPClient) CloseIdleConnections()                    {}

// signerFor lets the CSR tests reuse a software key through the same interface
// the flow uses.
var _ crypto.Signer = (*rsa.PrivateKey)(nil)
