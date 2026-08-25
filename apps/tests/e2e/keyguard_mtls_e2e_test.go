//go:build e2e && windows
// +build e2e,windows

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// End-to-end coverage for a non-exportable Windows KeyGuard (VBS-isolated) key driving the complete
// MSAL mTLS proof-of-possession flow:
//
//	public API -> developer code -> real credential -> token acquisition
//	  -> returned binding certificate -> resource call -> successful E2E
//
// Nothing here is simulated: the key lives in the VBS trustlet, the token comes from Entra, and the
// resource is the real Microsoft Graph mTLS host. This mirrors MSAL .NET's SNI mTLS PoP E2E coverage
// for a non-exportable VBS-protected certificate, including the negative case where the same bound
// token is presented without the client certificate.
//
// These tests compile and run only with the "e2e" build tag, on Windows, and only when a KeyGuard
// certificate thumbprint is supplied:
//
//	$env:KEYGUARD_E2E_THUMBPRINT = "<sha1 thumbprint>"
//	go test -tags e2e -run KeyGuard -v ./apps/tests/e2e/...
//
// See apps/tests/devapps/keyguard/README.md for how to provision the key.

package e2e

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/tests/devapps/keyguard/ncryptsigner"
)

// Environment variables that select the certificate and, optionally, the app registration. Only the
// thumbprint is required; everything else defaults to the same SN/I lab configuration the mtls_pop
// integration tests use.
const (
	keyguardThumbprintEnv    = "KEYGUARD_E2E_THUMBPRINT"
	keyguardStoreLocationEnv = "KEYGUARD_E2E_STORE_LOCATION"
	keyguardStoreNameEnv     = "KEYGUARD_E2E_STORE_NAME"
	keyguardClientIDEnv      = "KEYGUARD_E2E_CLIENT_ID"
	keyguardAuthorityEnv     = "KEYGUARD_E2E_AUTHORITY"
)

// The SN/I-allow-listed app, its tenant, and the Graph mTLS endpoint. These duplicate the constants
// in apps/tests/integration/mtls_pop_integration_test.go on purpose: that file is in package
// integration, which a test in package e2e cannot import, and moving the constants to a shared
// package would enlarge this change for no behavioral gain. They are public identifiers, not
// secrets. ESTS gates mtls_pop on the app and the resource both being allow-listed.
const (
	keyguardDefaultStoreLocation = "CurrentUser"
	keyguardDefaultStoreName     = "My"
	keyguardDefaultClientID      = "163ffef9-a313-45b4-ab2f-c7e2f5e0e23e"
	keyguardDefaultAuthority     = "https://login.microsoftonline.com/bea21ebe-8b64-4d06-9f6d-6a889b120a7c"

	// The regular graph.microsoft.com host does not perform a client-certificate handshake, so a
	// certificate-bound token has to be presented to the dedicated mTLS host.
	keyguardGraphScope        = "https://graph.microsoft.com/.default"
	keyguardGraphMtlsResource = "https://mtlstb.graph.microsoft.com/v1.0/applications?$top=1"
)

func envOrDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// openKeyGuardSigner opens the configured certificate and proves the key really is VBS-isolated
// before any test spends a network round trip on it. A green test against a software key would be
// worse than no test at all, so a key that is not isolated is a hard failure, not a skip.
func openKeyGuardSigner(t *testing.T) *ncryptsigner.Signer {
	t.Helper()

	thumbprint := os.Getenv(keyguardThumbprintEnv)
	if thumbprint == "" {
		t.Skipf("set %s to the SHA-1 thumbprint of a KeyGuard (VBS-isolated) certificate to run this test; "+
			"see apps/tests/devapps/keyguard/README.md for provisioning", keyguardThumbprintEnv)
	}
	storeLocation := envOrDefault(keyguardStoreLocationEnv, keyguardDefaultStoreLocation)
	storeName := envOrDefault(keyguardStoreNameEnv, keyguardDefaultStoreName)

	signer, err := ncryptsigner.Open(storeLocation, storeName, thumbprint)
	if err != nil {
		t.Fatalf("ncryptsigner.Open(%s, %s, %s) failed: %s", storeLocation, storeName, thumbprint, err)
	}
	t.Cleanup(signer.Close)

	isolated, err := signer.IsVirtualIsolated()
	if err != nil {
		t.Fatalf("querying the CNG isolation property failed: %s", err)
	}
	if !isolated {
		t.Fatalf("certificate %s in %s\\%s does not have a VBS-isolated (KeyGuard) key. This test exists "+
			"to prove the non-exportable path, so it must not pass against a software key: re-provision the "+
			"key with PKCS12_VIRTUAL_ISOLATION_KEY / -VirtualIsolation.",
			thumbprint, storeLocation, storeName)
	}

	// A one-element chain means CertGetCertificateChain silently degraded to leaf-only, which would
	// send an x5c with no intermediates. The lab certificate chains through a real intermediate, so
	// this guards the chain-building fix against a silent regression.
	if chain := signer.Chain(); len(chain) < 2 {
		t.Fatalf("signer.Chain() returned %d certificate(s), want at least 2 (leaf plus intermediate); "+
			"chain building degraded to leaf-only: %v", len(chain), signer.ChainError())
	}
	if err := signer.ChainError(); err != nil {
		t.Fatalf("chain building reported an error: %s", err)
	}
	return signer
}

// TestKeyGuardMtlsPoPEndToEnd drives the whole flow with a genuinely non-exportable key: it builds a
// credential from the public API, acquires a certificate-bound mtls_pop token from Entra, verifies
// the binding cryptographically, calls a real resource over mTLS with the certificate MSAL returned,
// and checks the negative case in which the same token is presented without the certificate.
func TestKeyGuardMtlsPoPEndToEnd(t *testing.T) {
	signer := openKeyGuardSigner(t)

	t.Logf("certificate %s, chain of %d, VBS isolated", signer.Certificate().Subject, len(signer.Chain()))

	// The only integration point: a tls.Certificate whose PrivateKey is the CNG signer. No MSAL API
	// is Windows-specific and none was added for KeyGuard.
	cred, err := confidential.NewCredFromTLSCertificate(tls.Certificate{
		Certificate: signer.Chain(),
		PrivateKey:  signer,
	})
	if err != nil {
		t.Fatalf("confidential.NewCredFromTLSCertificate() failed: %s", err)
	}

	authority := envOrDefault(keyguardAuthorityEnv, keyguardDefaultAuthority)
	clientID := envOrDefault(keyguardClientIDEnv, keyguardDefaultClientID)
	app, err := confidential.New(authority, clientID, cred)
	if err != nil {
		t.Fatalf("confidential.New() failed: %s", err)
	}

	ctx := context.Background()
	scopes := []string{keyguardGraphScope}

	// WithMtlsProofOfPossession is mandatory for a non-exportable key: every other flow signs a
	// client assertion, which requires an *rsa.PrivateKey a KeyGuard key can never be.
	result, err := app.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("AcquireTokenByCredential() with mTLS PoP failed: %s", err)
	}
	if result.AccessToken == "" {
		t.Fatal("AcquireTokenByCredential() returned an empty AccessToken")
	}
	// Fail closed on a downgrade: a Bearer token here would mean the request was not actually
	// proof-of-possession, and every assertion below would be meaningless.
	if result.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("token_type = %q, want mtls_pop", result.Metadata.TokenType)
	}
	if result.Metadata.TokenSource != confidential.TokenSourceIdentityProvider {
		t.Fatal("the first AcquireTokenByCredential() did not reach the identity provider")
	}
	if result.BindingCertificate == nil {
		t.Fatal("the result carries no binding certificate, so the token is not certificate-bound")
	}
	if result.BindingCertificate.Leaf == nil {
		t.Fatal("the binding certificate has no parsed leaf")
	}

	// The binding certificate must still carry the CNG signer itself. Comparing identity (rather
	// than just non-nil) proves MSAL neither copied nor rebuilt the key: a regression that replaced
	// it with an exported software key would fail here even though the handshake might still work.
	if result.BindingCertificate.PrivateKey != signer {
		t.Fatal("the binding certificate's private key is not the CNG signer that was supplied; " +
			"the non-exportable key did not survive the round trip")
	}
	if got, want := len(result.BindingCertificate.Certificate), len(signer.Chain()); got != want {
		t.Fatalf("the binding certificate carries %d certificate(s), want %d: the chain did not reach x5c", got, want)
	}

	// The cnf (confirmation) claim is what actually binds the token. A successful resource call
	// proves the handshake worked, but a lenient resource could still accept a token bound to a
	// different key, so the claim is checked directly against what MSAL reported.
	cnf, err := cnfThumbprint(result.AccessToken)
	if err != nil {
		t.Fatalf("reading the token's confirmation claim failed: %s", err)
	}
	if cnf != result.BindingCertificateThumbprint() {
		t.Fatalf("cnf[\"x5t#S256\"] = %q, want %q: the token is bound to a different certificate than the "+
			"one MSAL returned", cnf, result.BindingCertificateThumbprint())
	}
	// ...and that MSAL's reported thumbprint is genuinely the SHA-256 of the KeyGuard leaf, not some
	// value that happens to match the claim.
	sum := sha256.Sum256(signer.Certificate().Raw)
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); cnf != want {
		t.Fatalf("cnf[\"x5t#S256\"] = %q, want %q (SHA-256 of the KeyGuard leaf certificate)", cnf, want)
	}

	t.Run("ResourceAcceptsBoundToken", func(t *testing.T) {
		// Present the token to a real resource with the binding certificate exactly as MSAL returned
		// it. The TLS handshake here is itself signed by the VBS-isolated key.
		status, body := callGraphMtls(t, result.AccessToken, result.BindingCertificate)
		t.Logf("resource responded HTTP %d with the binding certificate presented", status)
		if status != http.StatusOK {
			t.Fatalf("the resource did not accept the mtls_pop token: got HTTP %d, want 200. A 401 or 403 "+
				"means the binding certificate was not presented on the handshake, the app is not "+
				"allow-listed for mtls_pop, or the Authorization scheme was not \"mtls_pop\". Response: %s",
				status, body)
		}
	})

	t.Run("ResourceRejectsTokenWithoutClientCertificate", func(t *testing.T) {
		// The negative half of the proof: the identical token, sent without the client certificate,
		// must be refused. Without this, a resource that ignored the binding entirely would still
		// make the happy path pass. Graph answers with
		// 401 {"error":{"code":"InvalidAuthenticationToken","message":"MtlsMissingClientCertificate"}}.
		status, body := callGraphMtls(t, result.AccessToken, nil)
		t.Logf("resource responded HTTP %d without a client certificate: %s", status, body)
		if status != http.StatusUnauthorized {
			t.Fatalf("a bound token presented WITHOUT the client certificate returned HTTP %d, want 401. "+
				"The resource is not enforcing the certificate binding. Response: %s", status, body)
		}
		if !mentionsClientCertificate(body) {
			t.Errorf("the 401 response does not indicate a missing client certificate, so the rejection "+
				"may be unrelated to the binding. Response: %s", body)
		}
	})

	t.Run("SecondCallServedFromCache", func(t *testing.T) {
		cached, err := app.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
		if err != nil {
			t.Fatalf("the second AcquireTokenByCredential() failed: %s", err)
		}
		if cached.Metadata.TokenSource != confidential.TokenSourceCache {
			t.Fatal("the second AcquireTokenByCredential() did not come from the cache")
		}
		if cached.AccessToken != result.AccessToken {
			t.Fatal("the cached token does not match the originally issued token")
		}
		if cached.Metadata.TokenType != "mtls_pop" {
			t.Fatalf("the cached token_type = %q, want mtls_pop", cached.Metadata.TokenType)
		}
		// A cached result must still carry a usable binding certificate; without it the caller has a
		// bound token and no way to present it.
		if cached.BindingCertificate == nil || cached.BindingCertificate.PrivateKey == nil {
			t.Fatal("the cached result lost the binding certificate or its private key")
		}
		if cached.BindingCertificateThumbprint() != result.BindingCertificateThumbprint() {
			t.Fatalf("the cached binding thumbprint = %q, want %q",
				cached.BindingCertificateThumbprint(), result.BindingCertificateThumbprint())
		}
	})
}

// TestKeyGuardSignerOnlyRejectsAssertionFlows proves the guard rail from the other direction: the
// same credential used WITHOUT proof-of-possession has to fail fast with actionable guidance rather
// than attempt an assertion signature the key can never produce.
func TestKeyGuardSignerOnlyRejectsAssertionFlows(t *testing.T) {
	signer := openKeyGuardSigner(t)

	cred, err := confidential.NewCredFromTLSCertificate(tls.Certificate{
		Certificate: signer.Chain(),
		PrivateKey:  signer,
	})
	if err != nil {
		t.Fatalf("confidential.NewCredFromTLSCertificate() failed: %s", err)
	}
	app, err := confidential.New(
		envOrDefault(keyguardAuthorityEnv, keyguardDefaultAuthority),
		envOrDefault(keyguardClientIDEnv, keyguardDefaultClientID),
		cred,
	)
	if err != nil {
		t.Fatalf("confidential.New() failed: %s", err)
	}

	_, err = app.AcquireTokenByCredential(context.Background(), []string{keyguardGraphScope})
	if err == nil {
		t.Fatal("a non-exportable key produced a client assertion, which is impossible; the signer-only " +
			"guard is not being applied")
	}
	if !strings.Contains(err.Error(), "WithMtlsProofOfPossession") {
		t.Fatalf("the error does not point the caller at WithMtlsProofOfPossession(): %s", err)
	}
}

// cnfThumbprint extracts cnf["x5t#S256"] from an access token.
func cnfThumbprint(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("the access token is not a JWT: got %d segments, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decoding the JWT payload failed: %w", err)
	}
	var claims struct {
		Cnf map[string]string `json:"cnf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("parsing the JWT payload failed: %w", err)
	}
	if claims.Cnf["x5t#S256"] == "" {
		return "", fmt.Errorf(`the token carries no cnf["x5t#S256"] claim, so it is not certificate-bound`)
	}
	return claims.Cnf["x5t#S256"], nil
}

// callGraphMtls sends the token to the Graph mTLS host with the "mtls_pop" scheme, presenting
// bindingCert on the TLS handshake when it is non-nil. A nil bindingCert is the negative case: the
// same token, no client certificate. It returns the status and a truncated body, so callers decide
// what is a failure; the body is truncated because it lands in public CI logs.
func callGraphMtls(t *testing.T, token string, bindingCert *tls.Certificate) (int, string) {
	t.Helper()

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if bindingCert != nil {
		if bindingCert.PrivateKey == nil {
			t.Fatal("the binding certificate has no private key; it cannot be used for the mTLS handshake")
		}
		tlsConfig.Certificates = []tls.Certificate{*bindingCert}
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	req, err := http.NewRequest(http.MethodGet, keyguardGraphMtlsResource, nil)
	if err != nil {
		t.Fatalf("building the mTLS resource request failed: %s", err)
	}
	req.Header.Set("Authorization", "mtls_pop "+token)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("the mTLS resource call to %s failed: %s", keyguardGraphMtlsResource, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	// The reason a certificate-less call is refused often arrives in a header rather than the body.
	detail := strings.TrimSpace(string(body))
	if wwwAuth := resp.Header.Get("WWW-Authenticate"); wwwAuth != "" {
		detail = "WWW-Authenticate: " + wwwAuth + " | " + detail
	}
	return resp.StatusCode, detail
}

// mentionsClientCertificate reports whether a rejection actually blames the missing certificate.
// Graph answers the certificate-less call with code InvalidAuthenticationToken and message
// "MtlsMissingClientCertificate", which is the same marker MSAL .NET asserts on. The broader terms
// are kept as a fallback so a reworded message degrades to a weaker check rather than a red build,
// since the exact wording belongs to the resource, not to MSAL.
func mentionsClientCertificate(body string) bool {
	lowered := strings.ToLower(body)
	for _, marker := range []string{
		"mtlsmissingclientcertificate",
		"certificate",
		"mtls",
		"proof of possession",
		"proofofpossession",
	} {
		if strings.Contains(lowered, marker) {
			return true
		}
	}
	return false
}
