// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package integration

import (
	"context"
	"os"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
)

// mtlsPoPResourceScope is an ESTS allow-listed resource audience (Azure Key Vault). ESTS gates mTLS
// proof-of-possession on the final resource being allow-listed (see plan §e note A), so the E2E must
// request a token for an allow-listed resource regardless of the client app.
const mtlsPoPResourceScope = "https://vault.azure.net/.default"

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

	// A tenanted authority is required for mTLS PoP.
	app, err := confidential.New(microsoftAuthority, defaultClientId, cred)
	if err != nil {
		t.Fatalf("confidential.New() failed: %s", errors.Verbose(err))
	}

	ctx := context.Background()
	scopes := []string{mtlsPoPResourceScope}

	result, err := app.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("AcquireTokenByCredential() with mTLS PoP failed: %s", errors.Verbose(err))
	}
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

// TestTwoLegFICMtlsPoP_SNI is the Scope 2 (developer-orchestrated two-leg FIC over mTLS PoP) E2E
// test. Both legs are mTLS PoP: leg 1 uses the SNI cert as the TLS client certificate to obtain a
// certificate-bound federated assertion; leg 2 presents that assertion (client_assertion_type=
// jwt-pop) together with the same binding certificate to obtain the final mtls_pop token.
//
// It is skip-gated until ESTS confirms the FIC leg-2 contract and the resource audience is
// allow-listed for mTLS PoP in the lab (plan §h open questions 1-2). Set MSAL_RUN_FIC_MTLS_E2E=1 to
// enable it once the lab app + ESTS support are provisioned.
func TestTwoLegFICMtlsPoP_SNI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	if os.Getenv("MSAL_RUN_FIC_MTLS_E2E") == "" {
		t.Skip("skipping two-leg FIC mTLS PoP E2E: pending ESTS leg-2 contract + allow-listed resource confirmation (plan §h). Set MSAL_RUN_FIC_MTLS_E2E=1 to enable.")
	}

	cert, privateKey, err := getCertDataFromFile(pemFile)
	if err != nil {
		t.Fatalf("getCertDataFromFile() failed: %s", errors.Verbose(err))
	}
	ctx := context.Background()

	// Leg 1: SNI cert -> cert-bound federated assertion, itself an mTLS PoP request.
	leg1Cred, err := confidential.NewCredFromCert(cert, privateKey)
	if err != nil {
		t.Fatalf("leg 1 NewCredFromCert() failed: %s", errors.Verbose(err))
	}
	leg1App, err := confidential.New(authorityURL, testClientID, leg1Cred)
	if err != nil {
		t.Fatalf("leg 1 confidential.New() failed: %s", errors.Verbose(err))
	}
	leg1, err := leg1App.AcquireTokenByCredential(ctx, []string{fmiScope},
		confidential.WithFMIPath(fmiPath),
		confidential.WithMtlsProofOfPossession(),
	)
	if err != nil {
		t.Fatalf("leg 1 AcquireTokenByCredential() failed: %s", errors.Verbose(err))
	}
	if leg1.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("leg 1 token_type = %q, want mtls_pop", leg1.Metadata.TokenType)
	}
	if leg1.BindingCertificate == nil {
		t.Fatal("leg 1 result missing binding certificate")
	}

	// Leg 2: federated assertion (jwt-pop) + binding cert -> final mtls_pop token.
	leg2Cred := confidential.NewCredFromAssertionCallback(
		func(context.Context, confidential.AssertionRequestOptions) (string, error) {
			return leg1.AccessToken, nil
		},
	)
	leg2App, err := confidential.New(authorityURL, fmiClientID, leg2Cred)
	if err != nil {
		t.Fatalf("leg 2 confidential.New() failed: %s", errors.Verbose(err))
	}
	final, err := leg2App.AcquireTokenByCredential(ctx, []string{testScope},
		confidential.WithFMIPath(fmiPath),
		confidential.WithMtlsProofOfPossession(confidential.WithMtlsBindingCertificate(cert, privateKey)),
	)
	if err != nil {
		t.Fatalf("leg 2 AcquireTokenByCredential() failed: %s", errors.Verbose(err))
	}
	if final.AccessToken == "" {
		t.Fatal("leg 2 returned empty AccessToken")
	}
	if final.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("final token_type = %q, want mtls_pop", final.Metadata.TokenType)
	}
	// The final token is bound to the leg-1 certificate thumbprint.
	if final.BindingCertificateThumbprint() != leg1.BindingCertificateThumbprint() {
		t.Fatal("final token is not bound to the leg-1 certificate thumbprint")
	}
}
