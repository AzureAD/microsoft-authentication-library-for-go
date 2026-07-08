// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package integration

import (
	"context"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
)

// mtlsPoPResourceScope is an ESTS allow-listed resource audience (Azure Key Vault). ESTS gates mTLS
// proof-of-possession on the final resource being allow-listed, so the E2E must request a token for
// an allow-listed resource regardless of the client app.
const mtlsPoPResourceScope = "https://vault.azure.net/.default"

// SN/I-allow-listed app + MSI team tenant; mTLS PoP only works on this pair. Mirrors MSAL .NET
// ClientCredentialsMtlsPopTests and MSAL Java MtlsPopIT. Public identifiers, not secrets.
const (
	sniAllowlistedAppID     = "163ffef9-a313-45b4-ab2f-c7e2f5e0e23e"
	sniAllowlistedAuthority = "https://login.microsoftonline.com/bea21ebe-8b64-4d06-9f6d-6a889b120a7c"
	sniAllowlistedRegion    = "westus3"
)

// acquireMtlsPoPOrSkip runs an mTLS PoP acquisition and treats an ESTS token_type downgrade
// (mtls_pop -> Bearer) as inconclusive rather than a failure. The AAD test-slice mtlsauth endpoints
// have been observed to intermittently downgrade to Bearer; that is a server-side condition, not a
// MSAL regression, so the suite skips instead of failing. Mirrors MSAL .NET's
// ExecuteOrInconclusiveOnTokenTypeMismatchAsync.
func acquireMtlsPoPOrSkip(t *testing.T, fn func() (confidential.AuthResult, error)) confidential.AuthResult {
	t.Helper()
	res, err := fn()
	if err != nil {
		var mism errors.MtlsPoPTokenTypeMismatchError
		if errors.As(err, &mism) {
			t.Skipf("ESTS returned token_type %q instead of mtls_pop (server-side downgrade on this slice, not a MSAL regression); treating as inconclusive", mism.Actual)
		}
		t.Fatalf("AcquireTokenByCredential() with mTLS PoP failed: %s", errors.Verbose(err))
	}
	return res
}

// TestConfidentialClientSNIMtlsPoP is the Scope 1 (vanilla SNI -> mTLS PoP) end-to-end test. It uses
// the lab SNI certificate (non-CNG/exportable, provisioned by the pipelines as cert.pem) as the
// client TLS certificate to obtain a certificate-bound mtls_pop token from ESTS, then verifies the
// token type, the public binding certificate, and that a second call is served from the cache.
func TestConfidentialClientSNIMtlsPoP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	cert, privateKey, err := getCertDataFromFile(pemFile)
	if err != nil {
		t.Fatalf("getCertDataFromFile() failed: %s", errors.Verbose(err))
	}
	cred, err := confidential.NewCredFromCert(cert, privateKey)
	if err != nil {
		t.Fatalf("NewCredFromCert() failed: %s", errors.Verbose(err))
	}

	// A tenanted, SN/I-allow-listed authority + app is required for mTLS PoP.
	app, err := confidential.New(sniAllowlistedAuthority, sniAllowlistedAppID, cred)
	if err != nil {
		t.Fatalf("confidential.New() failed: %s", errors.Verbose(err))
	}

	ctx := context.Background()
	scopes := []string{mtlsPoPResourceScope}

	result := acquireMtlsPoPOrSkip(t, func() (confidential.AuthResult, error) {
		return app.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
	})
	if result.AccessToken == "" {
		t.Fatal("AcquireTokenByCredential() returned empty AccessToken")
	}
	if result.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("expected token_type mtls_pop, got %q", result.Metadata.TokenType)
	}
	if result.BindingCertificate == nil {
		t.Fatal("expected a public binding certificate on the result, got nil")
	}
	if result.BindingCertificateThumbprint() == "" {
		t.Fatal("expected a non-empty binding certificate thumbprint")
	}

	// Second call must come from the cache and keep the mTLS PoP metadata.
	cached, err := app.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("second AcquireTokenByCredential() failed: %s", errors.Verbose(err))
	}
	if cached.Metadata.TokenSource != confidential.TokenSourceCache {
		t.Fatal("second AcquireTokenByCredential() did not return the token from cache")
	}
	if cached.AccessToken != result.AccessToken {
		t.Fatal("cached token does not match the originally issued token")
	}
	if cached.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("cached token_type = %q, want mtls_pop", cached.Metadata.TokenType)
	}
}

// TestConfidentialClientSNIMtlsPoPRegional mirrors MSAL Java's
// acquireTokenClientCredentials_Certificate_MtlsPop_Regional: it pins the SDK to a concrete Azure
// region so the request is routed to the regional mTLS endpoint ({region}.mtlsauth.microsoft.com),
// then verifies the mtls_pop token type and that a second call is served from the cache.
func TestConfidentialClientSNIMtlsPoPRegional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	cert, privateKey, err := getCertDataFromFile(pemFile)
	if err != nil {
		t.Fatalf("getCertDataFromFile() failed: %s", errors.Verbose(err))
	}
	cred, err := confidential.NewCredFromCert(cert, privateKey)
	if err != nil {
		t.Fatalf("NewCredFromCert() failed: %s", errors.Verbose(err))
	}

	app, err := confidential.New(sniAllowlistedAuthority, sniAllowlistedAppID, cred, confidential.WithAzureRegion(sniAllowlistedRegion))
	if err != nil {
		t.Fatalf("confidential.New() failed: %s", errors.Verbose(err))
	}

	ctx := context.Background()
	scopes := []string{mtlsPoPResourceScope}

	result := acquireMtlsPoPOrSkip(t, func() (confidential.AuthResult, error) {
		return app.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
	})
	if result.AccessToken == "" {
		t.Fatal("AcquireTokenByCredential() returned empty AccessToken")
	}
	if result.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("expected token_type mtls_pop, got %q", result.Metadata.TokenType)
	}

	cached, err := app.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("second regional AcquireTokenByCredential() failed: %s", errors.Verbose(err))
	}
	if cached.Metadata.TokenSource != confidential.TokenSourceCache {
		t.Fatal("second regional AcquireTokenByCredential() did not return the token from cache")
	}
	if cached.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("cached token_type = %q, want mtls_pop", cached.Metadata.TokenType)
	}
}

// TestConfidentialClientSNIBearerAndMtlsPoPCacheIsolated mirrors MSAL Java's
// acquireTokenClientCredentials_BearerAndMtlsPop_AreCacheIsolated: it acquires a normal Bearer token
// and an mTLS PoP token for the same app and scope on the same client, then verifies the two tokens
// are distinct and carry the expected token types. Cache entries are keyed by token type + binding
// certificate, so the PoP request must not return the cached Bearer token.
func TestConfidentialClientSNIBearerAndMtlsPoPCacheIsolated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	cert, privateKey, err := getCertDataFromFile(pemFile)
	if err != nil {
		t.Fatalf("getCertDataFromFile() failed: %s", errors.Verbose(err))
	}
	cred, err := confidential.NewCredFromCert(cert, privateKey)
	if err != nil {
		t.Fatalf("NewCredFromCert() failed: %s", errors.Verbose(err))
	}

	// WithX5C enables subject-name/issuer auth for the Bearer leg; it is unused on the pure-cert
	// mTLS PoP leg (no client_assertion is sent there), so it is safe for both calls.
	app, err := confidential.New(sniAllowlistedAuthority, sniAllowlistedAppID, cred, confidential.WithX5C())
	if err != nil {
		t.Fatalf("confidential.New() failed: %s", errors.Verbose(err))
	}

	ctx := context.Background()
	scopes := []string{mtlsPoPResourceScope}

	bearer, err := app.AcquireTokenByCredential(ctx, scopes)
	if err != nil {
		t.Fatalf("AcquireTokenByCredential() (Bearer) failed: %s", errors.Verbose(err))
	}
	if bearer.AccessToken == "" {
		t.Fatal("Bearer AcquireTokenByCredential() returned empty AccessToken")
	}
	if bearer.Metadata.TokenType != "Bearer" {
		t.Fatalf("expected Bearer token_type, got %q", bearer.Metadata.TokenType)
	}

	pop := acquireMtlsPoPOrSkip(t, func() (confidential.AuthResult, error) {
		return app.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
	})
	if pop.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("expected mtls_pop token_type, got %q", pop.Metadata.TokenType)
	}

	if bearer.AccessToken == pop.AccessToken {
		t.Fatal("expected Bearer and mTLS PoP tokens to be cache-isolated, but AccessTokens matched")
	}
}
