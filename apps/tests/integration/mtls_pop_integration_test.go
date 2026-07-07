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
