// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package integration

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// mtlsMissingCertMarker is the error code the Graph mTLS host returns when an mtls_pop token arrives
// without the client certificate it is bound to. requireTokenRejectedWithoutCertificate asserts on
// this marker and not on the status code alone, because it is the only part of the response that
// attributes the rejection specifically to the absent certificate. Mirrors MSAL .NET PR #6167, which
// asserts on the same marker.
const mtlsMissingCertMarker = "MtlsMissingClientCertificate"

// SN/I-allow-listed app + MSI team tenant; mTLS PoP only works on this pair. Mirrors MSAL .NET
// ClientCredentialsMtlsPopTests and MSAL Java MtlsPopIT. Public identifiers, not secrets.
const (
	sniAllowlistedAppID     = "163ffef9-a313-45b4-ab2f-c7e2f5e0e23e"
	sniAllowlistedAuthority = "https://login.microsoftonline.com/bea21ebe-8b64-4d06-9f6d-6a889b120a7c"
	sniAllowlistedRegion    = "westus3"
)

// tokenExchangeScope is the audience the first leg of a two-leg S2S FIC exchange requests: it yields a
// federated assertion rather than a resource token. Mirrors MSAL .NET's TokenExchangeUrl.
const tokenExchangeScope = "api://AzureADTokenExchange/.default"

// checkTokenBoundToCertificate verifies that an mtls_pop access token actually names cert as its
// binding certificate, via the cnf (confirmation) claim's x5t#S256 thumbprint. A successful call to a
// resource proves the TLS handshake worked, but a lenient resource could still accept a token bound
// to something else, so the claim is checked directly. It returns an error rather than failing the
// test so the check itself can be unit-tested with a deliberately mismatched token.
func checkTokenBoundToCertificate(token string, cert *x509.Certificate) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("access token is not a JWT: got %d segments, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decoding the JWT payload failed: %w", err)
	}
	var claims struct {
		Cnf map[string]string `json:"cnf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("parsing the JWT payload failed: %w", err)
	}
	got := claims.Cnf["x5t#S256"]
	if got == "" {
		return fmt.Errorf(`the token carries no cnf["x5t#S256"] claim, so it is not certificate-bound`)
	}
	sum := sha256.Sum256(cert.Raw)
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got != want {
		return fmt.Errorf(`cnf["x5t#S256"] = %q, want %q: the token is bound to a different certificate `+
			"than the one MSAL returned on the result", got, want)
	}
	return nil
}

// requireTokenAcceptedByResource proves an mtls_pop token is actually usable end-to-end: it presents
// the token's binding certificate as the client certificate on the TLS handshake to the Microsoft
// Graph mTLS host and sends "Authorization: mtls_pop <token>", then requires HTTP 200. The app and
// certificate are allow-listed for mtls_pop here, so a 401/403 signals a real regression (the binding
// certificate was not presented on the handshake, or the wrong Authorization scheme was used), not an
// environment problem. bindingCert is AuthResult.BindingCertificate exactly as MSAL returned it — the
// test deliberately does not reassemble it, so a regression that strips the private key fails here.
// The helper is reused by the two-leg FIC E2E (PR #633), which presents leg 1's binding certificate.
// Mirrors MSAL .NET's CallResourceOverMtlsPopAsync.
func requireTokenAcceptedByResource(t *testing.T, token string, bindingCert *tls.Certificate) {
	t.Helper()

	if bindingCert == nil {
		t.Fatal("result has no binding certificate; cannot present it on the mTLS handshake")
	}
	if bindingCert.PrivateKey == nil {
		t.Fatal("binding certificate has no private key; it cannot be used for the mTLS handshake")
	}
	if bindingCert.Leaf == nil {
		t.Fatal("binding certificate has no parsed leaf; cannot verify what the token is bound to")
	}

	// Check the binding before spending a network round trip on it: this distinguishes "the token
	// is bound to the wrong certificate" from "the resource rejected the call", which the HTTP
	// status alone cannot.
	if err := checkTokenBoundToCertificate(token, bindingCert.Leaf); err != nil {
		t.Fatalf("the mtls_pop token is not bound to the binding certificate MSAL returned: %s", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{*bindingCert},
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

// requireTokenRejectedWithoutCertificate is the negative control for requireTokenAcceptedByResource.
// The HTTP 200 that helper requires proves the token is usable, but on its own it does not prove the
// resource is enforcing the certificate binding: a resource that ignored client certificates
// entirely would answer 200 just the same. Only a controlled negative separates those two worlds.
//
// So this replays the *identical* request - same token, same URL, same "Authorization: mtls_pop
// <token>" header, same timeout and TLS floor - and changes exactly one thing: no client certificate
// is offered on the handshake. Because that is the only variable, a rejection here can only be
// attributed to the missing certificate. Anything that made the two calls differ in some other way
// (a different URL, a re-acquired token, a different auth scheme) would break that attribution and
// leave the test proving nothing, so keep them in lockstep.
//
// The assertion is on mtlsMissingCertMarker rather than on the status code alone: a bare 401 could
// equally mean the token expired or was malformed, neither of which says anything about enforcement.
// The marker is what pins the failure to the absent certificate. Mirrors MSAL .NET PR #6167.
func requireTokenRejectedWithoutCertificate(t *testing.T, token string) {
	t.Helper()

	// No Certificates on the TLS config: this omission is the single variable under test.
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	req, err := http.NewRequest(http.MethodGet, graphMtlsResourceURL, nil)
	if err != nil {
		t.Fatalf("building the certificate-less mTLS resource request failed: %s", err)
	}
	req.Header.Set("Authorization", "mtls_pop "+token)

	resp, err := client.Do(req)
	if err != nil {
		// A transport-level failure is deliberately not accepted as proof of enforcement: a DNS
		// failure or a timeout would be indistinguishable from a refused handshake. If the resource
		// ever moves enforcement down to the TLS layer and rejects the certificate-less handshake
		// outright, it will surface here, and this check should then be relaxed deliberately rather
		// than by accident.
		t.Fatalf("the certificate-less call to %s failed before any HTTP response was received: %s",
			graphMtlsResourceURL, err)
	}
	defer resp.Body.Close()

	// Truncate the external response body before emitting it into (public) CI logs. The marker sits
	// in the first ~80 bytes of the resource's error envelope, well inside this limit.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	if resp.StatusCode == http.StatusOK {
		t.Fatalf("the resource returned HTTP 200 for an mtls_pop token presented WITHOUT its binding "+
			"certificate. The resource is therefore not enforcing the certificate binding at all, which "+
			"means the HTTP 200 in requireTokenAcceptedByResource proves only that the token was accepted, "+
			"not that proof-of-possession was checked. Response: %s", string(body))
	}
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected the resource to reject the certificate-less call with HTTP 401 or 403, got HTTP "+
			"%d. An unexpected status means the call never reached the mTLS enforcement path, so this "+
			"negative control is not proving anything and needs to be re-verified against the resource. "+
			"Response: %s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), mtlsMissingCertMarker) {
		t.Fatalf("the resource rejected the certificate-less call with HTTP %d, but the response does not "+
			"contain %q, so the rejection cannot be attributed to the missing binding certificate - an "+
			"expired or malformed token would look the same from here. Response: %s",
			resp.StatusCode, mtlsMissingCertMarker, string(body))
	}
}

// TestCredential_X509_Output_Pop is the SNI X509 -> mtls_pop end-to-end test on the global endpoint.
// It uses the lab SN/I certificate (provisioned by the pipelines as cert.pem) as the client TLS
// certificate to obtain a Graph-scoped, certificate-bound mtls_pop token, verifies the token type and
// public binding certificate, then calls Microsoft Graph over mTLS with that certificate to prove the
// token is actually accepted by a resource (HTTP 200). It then replays that same call without the
// certificate to prove the resource is genuinely enforcing the binding rather than ignoring client
// certificates. A second call must be served from the cache. Mirrors MSAL .NET's
// Credential_X509_Output_Pop.
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
		t.Fatal("expected a binding certificate on the result, got nil")
	}
	if result.BindingCertificate.Leaf == nil {
		t.Fatal("expected the binding certificate's parsed leaf, got nil")
	}
	if result.BindingCertificate.PrivateKey == nil {
		t.Fatal("expected the binding certificate to carry its private key, got nil")
	}
	if result.BindingCertificateThumbprint() == "" {
		t.Fatal("expected a non-empty binding certificate thumbprint")
	}

	// Prove the token is usable by a resource: present it to Microsoft Graph over mTLS with the bound
	// certificate exactly as MSAL returned it. This is the strict "200-or-fail" check that a mere
	// acquisition assertion cannot make.
	requireTokenAcceptedByResource(t, result.AccessToken, result.BindingCertificate)

	// The 200 above proves the token is accepted, not that the binding is enforced. Replay the same
	// call with the same token and no client certificate; it must be rejected. This lives on this
	// test only: enforcement is a property of the resource, not of each acquisition path, so
	// repeating it on the other cells would spend extra round trips for no additional proof.
	requireTokenRejectedWithoutCertificate(t, result.AccessToken)

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
	// WithAzureRegion pins the regional token endpoint, keeping live regional coverage on this
	// deterministic Bearer cell. Do not remove it.
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
// jwt-pop) together with the same binding certificate to obtain the final mtls_pop token, which is
// then presented to Microsoft Graph over mTLS to prove it is accepted by a real resource.
//
// Leg 2 uses NewCredFromSignedAssertionCallback, the paired handoff API, so this test covers the
// exact path applications are meant to use to carry leg 1's assertion and certificate forward
// together rather than through two independent options.
//
// Both legs use the SN/I allow-listed app in the MSI team tenant and the global (non-regional)
// endpoint, which is the only configuration ESTS enables for mTLS PoP. Like the SNI tests, both legs
// fail closed on an ESTS token_type downgrade (mtls_pop -> Bearer) rather than treating it as
// inconclusive. Mirrors MSAL .NET's Credential_Fic_Output_Pop_TestAsync /
// RunTwoLegS2sFicBothLegsPopAsync.
func TestTwoLegFICMtlsPoP_SNI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
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
	leg1App, err := confidential.New(sniAllowlistedAuthority, sniAllowlistedAppID, leg1Cred)
	if err != nil {
		t.Fatalf("leg 1 confidential.New() failed: %s", errors.Verbose(err))
	}
	leg1, err := leg1App.AcquireTokenByCredential(ctx, []string{tokenExchangeScope},
		confidential.WithMtlsProofOfPossession(),
	)
	if err != nil {
		t.Fatalf("leg 1 AcquireTokenByCredential() with mTLS PoP failed: %s", errors.Verbose(err))
	}
	if leg1.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("leg 1 token_type = %q, want mtls_pop", leg1.Metadata.TokenType)
	}
	if leg1.AccessToken == "" {
		t.Fatal("leg 1 did not return a federated assertion")
	}
	if leg1.BindingCertificate == nil {
		t.Fatal("leg 1 result missing binding certificate")
	}

	// Leg 2: federated assertion (jwt-pop) + the SAME binding certificate -> final mtls_pop token.
	// The assertion and the certificate are handed over as one SignedAssertion, which is the API
	// that makes the pairing atomic: a rotation between the two legs can't pair one leg's assertion
	// with another leg's certificate, and a regression that strips the private key or swaps the
	// certificate fails here rather than silently rebinding.
	leg2Cred := confidential.NewCredFromSignedAssertionCallback(
		func(context.Context, confidential.AssertionRequestOptions) (confidential.SignedAssertion, error) {
			return confidential.SignedAssertion{
				Assertion:          leg1.AccessToken,
				BindingCertificate: leg1.BindingCertificate,
			}, nil
		},
	)
	leg2App, err := confidential.New(sniAllowlistedAuthority, sniAllowlistedAppID, leg2Cred)
	if err != nil {
		t.Fatalf("leg 2 confidential.New() failed: %s", errors.Verbose(err))
	}
	final, err := leg2App.AcquireTokenByCredential(ctx, []string{graphMtlsScope},
		confidential.WithMtlsProofOfPossession(),
	)
	if err != nil {
		t.Fatalf("leg 2 AcquireTokenByCredential() with mTLS PoP failed: %s", errors.Verbose(err))
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

	// The final token must be accepted by a real resource over mTLS.
	requireTokenAcceptedByResource(t, final.AccessToken, final.BindingCertificate)
}

// TestConfidentialClientSNIBearerAndMtlsPoPCacheIsolated mirrors MSAL Java's
// acquireTokenClientCredentials_BearerAndMtlsPop_AreCacheIsolated: it acquires a normal Bearer token
// and an mTLS PoP token for the same app and scope on the same client, then verifies the two tokens
// are distinct and carry the expected token types. The access token cache key includes the token
// type, so the PoP request must not return the cached Bearer token. The binding certificate's
// thumbprint is not part of the cache write key; it is applied as a read-side filter (KeyId,
// x5t#S256) when a cached token is served.
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

// TestCredential_X509_Output_Pop_Regional is the regional counterpart to
// TestCredential_X509_Output_Pop: the same SN/I certificate and app, but with WithAzureRegion, so the
// token request goes to {region}.mtlsauth.microsoft.com instead of the global endpoint. Regional mTLS
// PoP is supported and returns token_type=mtls_pop; it is not forbidden or degraded. Modeled on the
// ESTS contract test SniMtlsCertificateTests (MISE.ContractTesting), which uses the same allow-listed
// region and asserts on the token only, without calling a resource.
//
// This cell also covers the region write-back fix: an mTLS PoP request with a region configured must
// reach the regionalized mtlsauth host rather than silently falling back to the global one.
//
// The Bearer regional cell (TestCredential_X509_Output_Bearer) is deliberately kept as-is; it is a
// faithful port of MSAL .NET's Credential_X509_Output_Bearer and covers a different endpoint.
func TestCredential_X509_Output_Pop_Regional(t *testing.T) {
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

	app, err := confidential.New(sniAllowlistedAuthority, sniAllowlistedAppID, cred,
		confidential.WithAzureRegion(sniAllowlistedRegion))
	if err != nil {
		t.Fatalf("confidential.New() failed: %s", errors.Verbose(err))
	}

	ctx := context.Background()
	scopes := []string{mtlsPoPResourceScope}

	result, err := app.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("regional AcquireTokenByCredential() with mTLS PoP failed: %s", errors.Verbose(err))
	}
	if result.AccessToken == "" {
		t.Fatal("regional AcquireTokenByCredential() returned empty AccessToken")
	}
	// Fail closed on a downgrade: a regional endpoint that answered with Bearer would mean the
	// request was not actually proof-of-possession.
	if result.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("regional token_type = %q, want mtls_pop", result.Metadata.TokenType)
	}
	if result.BindingCertificate == nil || result.BindingCertificate.Leaf == nil {
		t.Fatal("regional mTLS PoP result carries no usable binding certificate")
	}
	if err := checkTokenBoundToCertificate(result.AccessToken, result.BindingCertificate.Leaf); err != nil {
		t.Fatalf("regional mtls_pop token is not bound to the returned certificate: %s", err)
	}

	// Second call must be served from the cache.
	cached, err := app.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("second regional AcquireTokenByCredential() failed: %s", errors.Verbose(err))
	}
	if cached.Metadata.TokenSource != confidential.TokenSourceCache {
		t.Fatal("second regional AcquireTokenByCredential() did not come from the cache")
	}
	if cached.AccessToken != result.AccessToken {
		t.Fatal("regional cached token does not match the originally issued token")
	}
	if cached.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("regional cached token_type = %q, want mtls_pop", cached.Metadata.TokenType)
	}
}

// TestConfidentialClientSNIMtlsPoPThenBearerCacheIsolated is the reverse of
// TestConfidentialClientSNIBearerAndMtlsPoPCacheIsolated: it acquires the mTLS PoP token FIRST and
// the Bearer token second. Acquisition order must not matter, and the order that runs second is the
// interesting one - a cached mtls_pop token must never be handed to a caller who did not ask for
// proof-of-possession, which is the more dangerous direction of the two (a caller who wanted a bound
// token and got a bearer token can at least detect it from the token type; a caller who wanted a
// plain bearer token and received a bound one will simply fail at the resource).
func TestConfidentialClientSNIMtlsPoPThenBearerCacheIsolated(t *testing.T) {
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

	app, err := confidential.New(sniAllowlistedAuthority, sniAllowlistedAppID, cred, confidential.WithX5C())
	if err != nil {
		t.Fatalf("confidential.New() failed: %s", errors.Verbose(err))
	}

	ctx := context.Background()
	scopes := []string{mtlsPoPResourceScope}

	pop, err := app.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("mTLS PoP AcquireTokenByCredential() failed: %s", errors.Verbose(err))
	}
	if pop.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("expected mtls_pop token_type, got %q", pop.Metadata.TokenType)
	}

	bearer, err := app.AcquireTokenByCredential(ctx, scopes)
	if err != nil {
		t.Fatalf("AcquireTokenByCredential() (Bearer) failed: %s", errors.Verbose(err))
	}
	if bearer.Metadata.TokenType != "Bearer" {
		t.Fatalf("expected token_type Bearer, got %q", bearer.Metadata.TokenType)
	}
	if bearer.BindingCertificate != nil {
		t.Fatal("a Bearer token must not carry a binding certificate")
	}
	if bearer.AccessToken == pop.AccessToken {
		t.Fatal("the Bearer request was served the cached mtls_pop token")
	}

	// The PoP token is still cached and still PoP, so the Bearer acquisition did not displace it.
	popAgain, err := app.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("second mTLS PoP AcquireTokenByCredential() failed: %s", errors.Verbose(err))
	}
	if popAgain.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("second PoP call token_type = %q, want mtls_pop", popAgain.Metadata.TokenType)
	}
	if popAgain.AccessToken != pop.AccessToken {
		t.Fatal("the mTLS PoP token was displaced by the Bearer acquisition")
	}
}
