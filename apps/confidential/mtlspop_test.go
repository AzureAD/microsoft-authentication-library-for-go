// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/fake"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

// mtlsTestCert generates an RSA cert and key for use in mTLS PoP unit tests.
func mtlsTestCert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test-mtls"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// mtlsFakeClient creates a confidential.Client wired to a fake.AccessTokens that returns
// the given TokenResponse. The client is configured with a cert credential and a tenanted
// authority.
func mtlsFakeClient(t *testing.T, tr accesstokens.TokenResponse, cert *x509.Certificate, key *rsa.PrivateKey, options ...Option) (Client, *fake.AccessTokens) {
	t.Helper()
	cred, err := NewCredFromCert([]*x509.Certificate{cert}, key)
	if err != nil {
		t.Fatal(err)
	}
	// Use a tenanted authority (required for mTLS PoP)
	tenantedAuthority := "https://login.microsoftonline.com/fakeTenant"
	client, err := New(tenantedAuthority, fakeClientID, cred, options...)
	if err != nil {
		t.Fatal(err)
	}
	fakeAT := &fake.AccessTokens{AccessToken: tr}
	client.base.Token.AccessTokens = fakeAT
	client.base.Token.Authority = &fake.Authority{
		InstanceResp: authority.InstanceDiscoveryResponse{
			TenantDiscoveryEndpoint: tenantedAuthority + "/discovery/endpoint",
			Metadata: []authority.InstanceDiscoveryMetadata{
				{
					PreferredNetwork: "login.microsoftonline.com",
					PreferredCache:   "login.microsoftonline.com",
					Aliases:          []string{"login.microsoftonline.com"},
				},
			},
		},
	}
	client.base.Token.Resolver = &fake.ResolveEndpoints{
		Endpoints: authority.NewEndpoints(
			tenantedAuthority+"/auth",
			tenantedAuthority+"/token",
			tenantedAuthority+"/jwt",
			tenantedAuthority,
		),
	}
	client.base.Token.WSTrust = &fake.WSTrust{}
	return client, fakeAT
}

// mtlsTokenResponse builds a fake mTLS PoP token response.
func mtlsTokenResponse() accesstokens.TokenResponse {
	return accesstokens.TokenResponse{
		AccessToken:   "fake_mtls_pop_token",
		TokenType:     "mtls_pop",
		RefreshOn:     internalTime.DurationTime{T: time.Now().Add(6 * time.Hour)},
		ExpiresOn:     time.Now().Add(12 * time.Hour),
		ExtExpiresOn:  internalTime.DurationTime{T: time.Now().Add(12 * time.Hour)},
		GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
	}
}

// TestWithMtlsProofOfPossession_RequiresCert verifies that WithMtlsProofOfPossession fails
// without a certificate credential.
func TestWithMtlsProofOfPossession_RequiresCert(t *testing.T) {
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	client, err := fakeClient(accesstokens.TokenResponse{}, cred, "https://login.microsoftonline.com/fakeTenant")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("WithMtlsProofOfPossession without cert: want cert error, got %v", err)
	}
}

// TestWithMtlsProofOfPossession_RequiresTenantedAuthority verifies that /common is rejected.
func TestWithMtlsProofOfPossession_RequiresTenantedAuthority(t *testing.T) {
	cert, key := mtlsTestCert(t)
	cred, err := NewCredFromCert([]*x509.Certificate{cert}, key)
	if err != nil {
		t.Fatal(err)
	}
	// common authority should fail
	client, err := New("https://login.microsoftonline.com/common", fakeClientID, cred,
		WithAzureRegion("eastus"))
	if err != nil {
		t.Fatal(err)
	}
	client.base.Token.Authority = &fake.Authority{
		InstanceResp: authority.InstanceDiscoveryResponse{
			TenantDiscoveryEndpoint: "https://login.microsoftonline.com/common/discovery/endpoint",
			Metadata: []authority.InstanceDiscoveryMetadata{
				{PreferredNetwork: "login.microsoftonline.com", PreferredCache: "login.microsoftonline.com"},
			},
		},
	}
	client.base.Token.Resolver = &fake.ResolveEndpoints{
		Endpoints: authority.NewEndpoints("a", "b", "c", "d"),
	}
	client.base.Token.WSTrust = &fake.WSTrust{}
	client.base.Token.AccessTokens = &fake.AccessTokens{}

	_, err = client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if err == nil || !strings.Contains(err.Error(), "tenanted") {
		t.Errorf("WithMtlsProofOfPossession on /common: want tenanted error, got %v", err)
	}
}

// TestWithMtlsProofOfPossession_RequiresRegion verifies that missing region is rejected.
func TestWithMtlsProofOfPossession_RequiresRegion(t *testing.T) {
	cert, key := mtlsTestCert(t)
	// No region configured
	client, fakeAT := mtlsFakeClient(t, accesstokens.TokenResponse{}, cert, key)
	_ = fakeAT

	_, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if err == nil || !strings.Contains(err.Error(), "region") {
		t.Errorf("WithMtlsProofOfPossession without region: want region error, got %v", err)
	}
}

// TestWithMtlsProofOfPossession_CallsFromMtlsCertificate verifies the mTLS path is used
// and that the auth scheme is set to mtls_pop.
func TestWithMtlsProofOfPossession_CallsFromMtlsCertificate(t *testing.T) {
	cert, key := mtlsTestCert(t)
	tr := mtlsTokenResponse()
	tr.BindingCertificate = cert

	client, _ := mtlsFakeClient(t, tr, cert, key, WithAzureRegion("eastus"))

	result, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("AcquireTokenByCredential with mTLS PoP: %v", err)
	}
	if result.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
	if result.BindingCertificate == nil {
		t.Error("expected BindingCertificate to be set on mTLS PoP result")
	}
}

// TestWithMtlsProofOfPossession_SetsBindingCertificate verifies AuthResult.BindingCertificate.
func TestWithMtlsProofOfPossession_SetsBindingCertificate(t *testing.T) {
	cert, key := mtlsTestCert(t)
	tr := mtlsTokenResponse()
	tr.BindingCertificate = cert

	client, _ := mtlsFakeClient(t, tr, cert, key, WithAzureRegion("eastus"))

	result, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("AcquireTokenByCredential with mTLS PoP: %v", err)
	}
	if result.BindingCertificate == nil {
		t.Error("AuthResult.BindingCertificate must be set for mTLS PoP tokens")
	}
}

// TestWithMtlsProofOfPossession_CacheKey_DiffersFromBearer ensures mTLS PoP tokens
// are cached separately from bearer tokens.
func TestWithMtlsProofOfPossession_CacheKey_DiffersFromBearer(t *testing.T) {
	cert, key := mtlsTestCert(t)

	bearerTR := accesstokens.TokenResponse{
		AccessToken:   "bearer_token",
		TokenType:     "Bearer",
		RefreshOn:     internalTime.DurationTime{T: time.Now().Add(6 * time.Hour)},
		ExpiresOn:     time.Now().Add(12 * time.Hour),
		ExtExpiresOn:  internalTime.DurationTime{T: time.Now().Add(12 * time.Hour)},
		GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
	}

	// Bearer client
	cred, err := NewCredFromCert([]*x509.Certificate{cert}, key)
	if err != nil {
		t.Fatal(err)
	}
	bearerClient, err := fakeClient(bearerTR, cred, "https://login.microsoftonline.com/fakeTenant")
	if err != nil {
		t.Fatal(err)
	}
	bearerResult, err := bearerClient.AcquireTokenByCredential(context.Background(), tokenScope)
	if err != nil {
		t.Fatalf("bearer AcquireTokenByCredential: %v", err)
	}

	// mTLS PoP client (same clientID + tenant, different auth scheme)
	mtlsTR := mtlsTokenResponse()
	mtlsTR.BindingCertificate = cert
	mtlsClient, _ := mtlsFakeClient(t, mtlsTR, cert, key, WithAzureRegion("eastus"))
	mtlsResult, err := mtlsClient.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("mTLS PoP AcquireTokenByCredential: %v", err)
	}

	if bearerResult.AccessToken == mtlsResult.AccessToken {
		t.Error("mTLS PoP and bearer tokens should be cached separately and have different values")
	}
}

// TestWithSendCertificateOverMtls_SetOnClient verifies the option is stored correctly.
func TestWithSendCertificateOverMtls_SetOnClient(t *testing.T) {
	cert, key := mtlsTestCert(t)
	cred, err := NewCredFromCert([]*x509.Certificate{cert}, key)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(fakeAuthority, fakeClientID, cred, WithSendCertificateOverMtls())
	if err != nil {
		t.Fatal(err)
	}
	if !client.sendCertOverMtls {
		t.Error("WithSendCertificateOverMtls: expected sendCertOverMtls=true")
	}
}

// TestAutoDetectRegionSentinel returns the sentinel value.
func TestAutoDetectRegionSentinel(t *testing.T) {
	if got := AutoDetectRegion(); got != "TryAutoDetect" {
		t.Errorf("AutoDetectRegion: want TryAutoDetect, got %q", got)
	}
}
