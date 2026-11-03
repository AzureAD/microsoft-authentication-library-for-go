// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	msalerrors "github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
)

func TestRegionalAttestationEndpoint(t *testing.T) {
	const fallback = "https://platform.attestation.example"
	for _, tc := range []struct {
		name        string
		environment string
		location    string
		want        string
	}{
		{"public", "AzurePublicCloud", "westus2", "https://westus2.attestation.microsoft.com"},
		{"government", "azureusgovernmentcloud", "usgovvirginia", "https://usgovvirginia.attestation.microsoftonline.us"},
		{"china", "AzureChinaCloud", "chinaeast2", "https://chinaeast2.attestation.partner.microsoftonline.cn"},
		{"bleu", "AzureBleuCloud", "francecentral", "https://francecentral.attestation.sovcloud-identity.fr"},
		{"unknown cloud", "PrivateCloud", "region1", fallback},
		{"missing cloud", "", "westus2", fallback},
		{"missing region", "AzurePublicCloud", "", fallback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := regionalAttestationEndpoint(tc.environment, tc.location, fallback); got != tc.want {
				t.Fatalf("regionalAttestationEndpoint = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAttestationUsesRegionalEndpointAndTenantID(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.computeBody = `{"azEnvironment":"AzurePublicCloud","location":"WestUS2"}`
	provider := newFakeKeyProvider()

	var endpoint, clientID string
	original := attestKeyGuardFn
	attestKeyGuardFn = func(gotEndpoint, gotClientID string, _ bindingKey) (string, error) {
		endpoint, clientID = gotEndpoint, gotClientID
		return stubAttestationJWT(t, time.Now().Add(time.Hour)), nil
	}
	t.Cleanup(func() { attestKeyGuardFn = original })

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if endpoint != "https://westus2.attestation.microsoft.com" {
		t.Fatalf("attestation endpoint = %q", endpoint)
	}
	if clientID != fake.tenantID {
		t.Fatalf("attestation client_id = %q, want tenant ID %q", clientID, fake.tenantID)
	}
}

func TestAttestationCacheDoesNotIncludeMetadataClientID(t *testing.T) {
	clearAttestationCache()
	t.Cleanup(clearAttestationCache)
	provider := newFakeKeyProvider()
	key, err := provider.getOrCreateKey(bindingKeyName)
	if err != nil {
		t.Fatal(err)
	}
	holder := shareKey(&key)
	t.Cleanup(func() { _ = holder.release() })

	calls := withCountedAttestation(t, func() string {
		return stubAttestationJWT(t, time.Now().Add(time.Hour))
	})
	const endpoint = "https://westus2.attestation.microsoft.com"
	if _, err := attestKeyGuardCached(context.Background(), endpoint, "tenant-a", key, holder); err != nil {
		t.Fatal(err)
	}
	if _, err := attestKeyGuardCached(context.Background(), endpoint, "tenant-b", key, holder); err != nil {
		t.Fatal(err)
	}
	if *calls != 1 {
		t.Fatalf("attestation calls = %d, want 1: cache key must remain endpoint plus key fingerprint", *calls)
	}
}

func TestAttestationFallsBackToPlatformEndpointWhenComputeMetadataFails(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.computeBody = `{not-json`
	provider := newFakeKeyProvider()

	var endpoint string
	original := attestKeyGuardFn
	attestKeyGuardFn = func(gotEndpoint, _ string, _ bindingKey) (string, error) {
		endpoint = gotEndpoint
		return stubAttestationJWT(t, time.Now().Add(time.Hour)), nil
	}
	t.Cleanup(func() { attestKeyGuardFn = original })

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if endpoint != fake.attestationEndpoint {
		t.Fatalf("attestation endpoint = %q, want platform fallback %q", endpoint, fake.attestationEndpoint)
	}
}

func TestAttestationComputeMetadataCancellationIsNotSilentlyIgnored(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())
	factory := client.httpClient.(*testMtlsFactoryClient)
	base := factory.client.(*http.Client)
	transport := base.Transport
	routed := *base
	routed.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == imdsComputePath {
			<-req.Context().Done()
			return nil, req.Context().Err()
		}
		return transport.RoundTrip(req)
	})
	factory.client = &routed

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := client.AcquireToken(ctx, "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithAttestationSupport())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AcquireToken = %v, want compute metadata cancellation", err)
	}
	if fake.countOf("issue") != 0 {
		t.Fatal("credential issuance continued after compute metadata cancellation")
	}
}

func TestDisableIMDSv2PreservesV1AndRefusesExplicitMtls(t *testing.T) {
	withCleanCaches(t)
	t.Setenv(disableIMDSv2EnvVar, "true")
	fake := newIMDSFake(t)
	fake.v1TokenBody = `{"access_token":"v1-token","token_type":"Bearer","expires_on":"4102444800","resource":"https://vault.azure.net"}`
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	caps, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if caps.MaxSupportedBindingStrength != MtlsBindingStrengthNone || caps.IsMtlsPoPSupportedByHost() {
		t.Fatalf("Capabilities = %+v, want no v2 mTLS support", caps)
	}
	if fake.countOf("metadata") != 0 {
		t.Fatal("capability discovery probed IMDSv2 despite the disable switch")
	}

	result, err := client.AcquireToken(context.Background(), "https://vault.azure.net")
	if err != nil {
		t.Fatalf("ordinary IMDSv1 AcquireToken: %v", err)
	}
	if result.AccessToken != "v1-token" {
		t.Fatalf("access token = %q, want v1-token", result.AccessToken)
	}

	fake.resetCalls()
	_, err = client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithForceRefresh())
	if !errors.Is(err, ErrMtlsPoPNotSupportedInIMDSv1) {
		t.Fatalf("explicit mTLS acquisition = %v, want ErrMtlsPoPNotSupportedInIMDSv1", err)
	}
	if fake.callCount() != 0 {
		t.Fatalf("explicit mTLS acquisition made requests %v instead of failing without downgrade", fake.calls)
	}
}

func TestDisableIMDSv2RefusesCachedExplicitMtls(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("priming IMDSv2 cache: %v", err)
	}
	t.Setenv(disableIMDSv2EnvVar, "true")
	fake.resetCalls()

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession())
	if !errors.Is(err, ErrMtlsPoPNotSupportedInIMDSv1) {
		t.Fatalf("cached explicit mTLS acquisition = %v, want ErrMtlsPoPNotSupportedInIMDSv1", err)
	}
	if fake.callCount() != 0 {
		t.Fatalf("cached explicit mTLS acquisition made requests %v instead of failing immediately", fake.calls)
	}
}

func TestTokenEndpointErrorIsInspectableCallErr(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.tokenFailures = 1
	fake.tokenFailureCode = http.StatusBadRequest
	fake.tokenFailureBody = `{"error":"invalid_request","error_description":"bad certificate request"}`
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	var callErr msalerrors.CallErr
	if !errors.As(err, &callErr) {
		t.Fatalf("AcquireToken error %T = %v, want errors.CallErr", err, err)
	}
	if callErr.Resp == nil || callErr.Resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("CallErr response = %#v", callErr.Resp)
	}
	body, readErr := io.ReadAll(callErr.Resp.Body)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(body), "invalid_request") {
		t.Fatalf("CallErr body = %q", body)
	}
	var tokenErr *entraTokenError
	if !errors.As(err, &tokenErr) || tokenErr.Code != "invalid_request" {
		t.Fatalf("internal token classification was lost: %v", err)
	}
}

func TestRestoreDeletesOnlyFailedCandidateAndFindsConcurrentReplacement(t *testing.T) {
	persisted := withCleanCaches(t)
	provider := newFakeKeyProvider()
	alias := "candidate-race"

	valid := testBindingCertificate(t, provider, bindingKeyName, now().Add(28*24*time.Hour))
	invalid := testBindingCertificate(t, provider, bindingKeyName, now().Add(30*24*time.Hour))
	replacement := testBindingCertificate(t, provider, bindingKeyName, now().Add(31*24*time.Hour))
	invalid.TenantID = "11111111-2222-3333-4444-555555555555"
	for _, cert := range []*bindingCertificate{valid, invalid, replacement} {
		cert.Endpoint = "https://mtlsauth.example"
		c := cert
		t.Cleanup(func() { _ = c.Close() })
	}
	persisted.write(alias, valid)
	persisted.write(alias, invalid)
	persisted.onDeleteCertificate = func() { persisted.write(alias, replacement) }

	got, ok := certCache.restore(alias, valid.ClientID, valid.TenantID, provider)
	if !ok {
		t.Fatal("restore did not rescan after deleting the failed candidate")
	}
	defer func() { _ = got.Close() }()
	if !bytes.Equal(got.TLS.Certificate[0], replacement.TLS.Certificate[0]) {
		t.Fatal("restore did not adopt the concurrently written replacement")
	}
	if persisted.deleteAlls != 0 {
		t.Fatalf("restore called deleteAll %d times and could erase a concurrent replacement", persisted.deleteAlls)
	}
	if persisted.count(alias) != 2 {
		t.Fatalf("persisted candidates = %d, want valid original plus replacement", persisted.count(alias))
	}
}
