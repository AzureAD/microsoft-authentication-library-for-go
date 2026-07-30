// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package integration

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
)

// mtlsPoPResourceScope is an ESTS allow-listed resource audience (Azure Key Vault). ESTS gates mTLS
// proof-of-possession on the final resource being allow-listed, so tests that only need a token (and
// do not call a resource) request one for this allow-listed resource regardless of the client app.
const mtlsPoPResourceScope = "https://vault.azure.net/.default"

// graphMtlsScope and graphMtlsResourceURL drive the strict end-to-end usability check: acquire a
// Graph-scoped, certificate-bound mtls_pop token, then present it to the Microsoft Graph *mTLS* host
// with the binding certificate on the TLS handshake. The regular graph.microsoft.com host does not
// perform the client-certificate handshake, so the dedicated mTLS host is required. Mirrors MSAL .NET
// ClientCredentialsMtlsPopTests (GraphAppScope + GraphMtlsResourceUri).
const (
	graphMtlsScope       = "https://graph.microsoft.com/.default"
	graphMtlsResourceURL = "https://mtlstb.graph.microsoft.com/v1.0/applications?$top=1"
)

// SN/I-allow-listed app + MSI team tenant; mTLS PoP only works on this pair. Mirrors MSAL .NET
// ClientCredentialsMtlsPopTests and MSAL Java MtlsPopIT. Public identifiers, not secrets.
const (
	sniAllowlistedAppID     = "163ffef9-a313-45b4-ab2f-c7e2f5e0e23e"
	sniAllowlistedAuthority = "https://login.microsoftonline.com/bea21ebe-8b64-4d06-9f6d-6a889b120a7c"
	sniAllowlistedRegion    = "westus3"
)

// requireTokenAcceptedByResource proves an mtls_pop token is actually usable end-to-end: it presents
// the token's binding certificate as the client certificate on the TLS handshake to the Microsoft
// Graph mTLS host and sends "Authorization: mtls_pop <token>", then requires HTTP 200. The app and
// certificate are allow-listed for mtls_pop here, so a 401/403 signals a real regression (the binding
// certificate was not presented on the handshake, or the wrong Authorization scheme was used), not an
// environment problem. The helper is reused by the two-leg FIC E2E (PR #633), which presents leg 1's
// binding certificate. Mirrors MSAL .NET's CallResourceOverMtlsPopAsync.
func requireTokenAcceptedByResource(t *testing.T, token string, bindingCert tls.Certificate) {
	t.Helper()

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{bindingCert},
				MinVersion:   tls.VersionTLS12,
			},
		},
	}

	req, err := http.NewRequest(http.MethodGet, graphMtlsResourceURL, nil)
	if err != nil {
		t.Fatalf("building the mTLS resource request failed: %s", err)
	}
	req.Header.Set("Authorization", "mtls_pop "+token)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("mTLS resource call to %s failed: %s", graphMtlsResourceURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Truncate the external response body before emitting it into (public) CI logs.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		t.Fatalf("resource did not accept the mTLS PoP token: got HTTP %d, want 200. A 401/403 means the "+
			"binding certificate was not presented on the TLS handshake or the Authorization scheme was not "+
			"\"mtls_pop\". Response: %s", resp.StatusCode, string(body))
	}
}

// bindingTLSCert pairs the public binding certificate from an AuthResult with the private key the
// caller already holds for the SN/I certificate, producing a client certificate to present on the
// mTLS handshake. AuthResult.BindingCertificate exposes only public certificate material, so the key
// must be supplied separately. Reused by the two-leg FIC E2E (PR #633).
func bindingTLSCert(t *testing.T, bindingCert *x509.Certificate, privateKey crypto.PrivateKey) tls.Certificate {
	t.Helper()
	if bindingCert == nil {
		t.Fatal("result has no binding certificate; cannot present it on the mTLS handshake")
	}
	return tls.Certificate{
		Certificate: [][]byte{bindingCert.Raw},
		PrivateKey:  privateKey,
		Leaf:        bindingCert,
	}
}

// acquireMtlsPoPOrSkip treats an ESTS token_type downgrade (mtls_pop -> Bearer) on the FIC legs as
// inconclusive rather than a failure. It is retained only for the skip-gated two-leg FIC E2E below;
// the SNI tests deliberately fail closed on a downgrade (see TestCredential_X509_Output_Pop). This
// escape hatch is slated for removal when the FIC E2E is hardened (PR #633 follow-up).
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

// TestCredential_X509_Output_Pop is the SNI X509 -> mtls_pop end-to-end test on the global endpoint.
// It uses the lab SN/I certificate (provisioned by the pipelines as cert.pem) as the client TLS
// certificate to obtain a Graph-scoped, certificate-bound mtls_pop token, verifies the token type and
// public binding certificate, then calls Microsoft Graph over mTLS with that certificate to prove the
// token is actually accepted by a resource (HTTP 200). A second call must be served from the cache.
// Mirrors MSAL .NET's Credential_X509_Output_Pop.
func TestCredential_X509_Output_Pop(t *testing.T) {
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
	scopes := []string{graphMtlsScope}

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

	// Prove the token is usable by a resource: present it to Microsoft Graph over mTLS with the bound
	// certificate. This is the strict "200-or-fail" check that a mere acquisition assertion cannot make.
	requireTokenAcceptedByResource(t, result.AccessToken, bindingTLSCert(t, result.BindingCertificate, privateKey))

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

// TestCredential_X509_Output_Bearer acquires a token with the same SN/I certificate credential but
// WITHOUT requesting proof-of-possession, so ESTS returns a plain Bearer token. A Bearer token is not
// certificate-bound, so there is no binding certificate and no resource-over-mTLS call. Mirrors MSAL
// .NET's Credential_X509_Output_Bearer.
func TestCredential_X509_Output_Bearer(t *testing.T) {
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

	// WithX5C enables subject-name/issuer auth; without WithMtlsProofOfPossession the credential still
	// signs and sends a client_assertion and ESTS returns a Bearer token.
	// WithAzureRegion pins the regional mTLS endpoint. A region is forbidden for mtls_pop (it can cause a
	// silent mtls_pop->Bearer downgrade), but it is correct and desirable on this deterministic Bearer
	// cell to keep live regional-endpoint coverage. Do not remove it.
	app, err := confidential.New(sniAllowlistedAuthority, sniAllowlistedAppID, cred, confidential.WithX5C(), confidential.WithAzureRegion(sniAllowlistedRegion))
	if err != nil {
		t.Fatalf("confidential.New() failed: %s", errors.Verbose(err))
	}

	ctx := context.Background()
	result, err := app.AcquireTokenByCredential(ctx, []string{mtlsPoPResourceScope})
	if err != nil {
		t.Fatalf("AcquireTokenByCredential() (Bearer) failed: %s", errors.Verbose(err))
	}
	if result.AccessToken == "" {
		t.Fatal("AcquireTokenByCredential() returned empty AccessToken")
	}
	if result.Metadata.TokenType != "Bearer" {
		t.Fatalf("expected token_type Bearer, got %q", result.Metadata.TokenType)
	}
	if result.BindingCertificate != nil {
		t.Fatal("a Bearer token must not carry a binding certificate")
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
	leg1 := acquireMtlsPoPOrSkip(t, func() (confidential.AuthResult, error) {
		return leg1App.AcquireTokenByCredential(ctx, []string{fmiScope},
			confidential.WithFMIPath(fmiPath),
			confidential.WithMtlsProofOfPossession(),
		)
	})
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
	final := acquireMtlsPoPOrSkip(t, func() (confidential.AuthResult, error) {
		return leg2App.AcquireTokenByCredential(ctx, []string{testScope},
			confidential.WithFMIPath(fmiPath),
			confidential.WithMtlsProofOfPossession(confidential.WithMtlsBindingCertificate(cert, privateKey)),
		)
	})
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

	// WithX5C enables subject-name/issuer auth for the Bearer leg; it is unused on the pure-cert mTLS
	// PoP leg (no client_assertion is sent there), so it is safe for both calls.
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
		t.Fatalf("expected token_type Bearer, got %q", bearer.Metadata.TokenType)
	}

	pop, err := app.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("mTLS PoP AcquireTokenByCredential() failed: %s", errors.Verbose(err))
	}
	if pop.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("expected mtls_pop token_type, got %q", pop.Metadata.TokenType)
	}

	if bearer.AccessToken == pop.AccessToken {
		t.Fatal("expected Bearer and mTLS PoP tokens to be cache-isolated, but AccessTokens matched")
	}
}
