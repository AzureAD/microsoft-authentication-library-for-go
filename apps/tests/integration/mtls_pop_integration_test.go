// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
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

// The markers below are the error codes the Graph mTLS host returns for the three ways a call can
// fail the certificate-binding contract. requireTokenRejectedByResource asserts on these and not on
// the status code alone: all three rejections are an HTTP 401 carrying the same
// "InvalidAuthenticationToken" error code, so only the marker attributes a rejection to the one
// thing its negative control changed. The three markers are mutually exclusive, which is what stops
// a control that started failing for some other reason from passing anyway.
//
// All three were captured from the live resource. Mirrors MSAL .NET PR #6167, which asserts on
// mtlsMissingCertMarker.
const (
	// mtlsMissingCertMarker: no client certificate was presented on the handshake at all.
	mtlsMissingCertMarker = "MtlsMissingClientCertificate"

	// mtlsWrongSchemeMarker: the binding certificate was presented, but the token was offered under
	// "Bearer", a scheme that carries no proof-of-possession. Distinct from mtlsMissingCertMarker
	// because the certificate is on the handshake here, so only the scheme can explain the
	// rejection. The resource validates the scheme before the binding, so this marker is returned
	// whatever certificate is presented and never overlaps with mtlsWrongCertMarker.
	//
	// This is a fixed server-side error string rather than an error code; if it ever proves
	// brittle, "Cnf claim not supported over" is the stable prefix to fall back to. Do not weaken
	// it to the bare HTTP status, which proves nothing here.
	mtlsWrongSchemeMarker = "Cnf claim not supported over Bearer protocol."

	// mtlsWrongCertMarker: a client certificate was presented under the right scheme, but it is not
	// the one named by the token's cnf claim. Distinct from mtlsMissingCertMarker, which is what
	// this same request returns when nothing is presented - confirmed against the live resource by
	// replaying it with a deliberately empty certificate. That distinction is what makes the
	// wrong-certificate control prove the resource compares the certificate against the binding,
	// rather than merely checking that some certificate exists.
	mtlsWrongCertMarker = "MtlsCnfClaimRequestDataValidationFailed"
)

// SN/I-allow-listed app + MSI team tenant; mTLS PoP only works on this pair. Mirrors MSAL .NET
// ClientCredentialsMtlsPopTests and MSAL Java MtlsPopIT. Public identifiers, not secrets.
const (
	sniAllowlistedAppID     = "163ffef9-a313-45b4-ab2f-c7e2f5e0e23e"
	sniAllowlistedAuthority = "https://login.microsoftonline.com/bea21ebe-8b64-4d06-9f6d-6a889b120a7c"
	sniAllowlistedRegion    = "westus3"
)

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

// mtlsNegativeControl describes one negative control for requireTokenAcceptedByResource: the single
// deviation from that positive call, and the marker that must attribute the rejection to it.
type mtlsNegativeControl struct {
	// deviation names the one thing this control changes relative to the positive call. It is
	// interpolated into every failure message below, so phrase it to read after "even though".
	deviation string
	// scheme is the Authorization scheme to send. "mtls_pop" matches the positive call.
	scheme string
	// clientCert is the certificate offered on the TLS handshake; nil offers none. The token's
	// binding certificate matches the positive call.
	clientCert *tls.Certificate
	// wantMarker is the error marker the resource must return. This, and not the status code, is
	// what pins the rejection to deviation.
	wantMarker string
}

// requireTokenRejectedByResource is the negative control for requireTokenAcceptedByResource. The
// HTTP 200 that helper requires proves the token is usable, but on its own it does not prove the
// resource is enforcing the certificate binding: a resource that ignored client certificates
// entirely would answer 200 just the same. Only a controlled negative separates those two worlds.
//
// So this replays the *identical* request - same token, same URL, same timeout and TLS floor - and
// changes exactly one thing, described by control. Because that is the only variable, a rejection
// can only be attributed to it. Anything that made the two calls differ in some other way (a
// different URL, a re-acquired token, two deviations at once) would break that attribution and
// leave the test proving nothing, so keep them in lockstep.
//
// The assertion is on control.wantMarker rather than on the status code alone: a bare 401 could
// equally mean the token expired or was malformed, neither of which says anything about
// enforcement. The marker is what pins the failure to the deviation - all three controls otherwise
// return an indistinguishable HTTP 401 with error code "InvalidAuthenticationToken". Mirrors MSAL
// .NET PR #6167.
func requireTokenRejectedByResource(t *testing.T, token string, control mtlsNegativeControl) {
	t.Helper()

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if control.clientCert != nil {
		// Deliberately GetClientCertificate and not Certificates. With Certificates, Go only sends
		// the certificate if it satisfies the server's CertificateRequest, and silently sends an
		// EMPTY certificate message if it does not. The Graph mTLS host currently advertises no
		// acceptable CAs, so today both spellings put the certificate on the wire - but were that
		// to change, the wrong-certificate control would silently stop presenting a certificate at
		// all and decay into a duplicate of the no-certificate control. GetClientCertificate forces
		// the certificate onto the wire unconditionally, so the control keeps testing what it says
		// it tests. (The wantMarker assertion is the backstop: such a decay would return
		// mtlsMissingCertMarker and fail here rather than pass silently.)
		cert := control.clientCert
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert, nil
		}
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	req, err := http.NewRequest(http.MethodGet, graphMtlsResourceURL, nil)
	if err != nil {
		t.Fatalf("building the mTLS resource request for the negative control (%s) failed: %s",
			control.deviation, err)
	}
	req.Header.Set("Authorization", control.scheme+" "+token)

	resp, err := client.Do(req)
	if err != nil {
		// A transport-level failure is deliberately not accepted as proof of enforcement: a DNS
		// failure or a timeout would be indistinguishable from a refused handshake. The resource
		// enforces all three of these controls at the application layer - verified live, where even
		// an untrusted, unrelated client certificate completes the handshake and is then rejected
		// with an HTTP 401 - so if the resource ever moves enforcement down to the TLS layer and
		// refuses the handshake outright, it will surface here, and this check should then be
		// relaxed deliberately rather than by accident.
		t.Fatalf("the negative control call to %s (%s) failed before any HTTP response was received: %s",
			graphMtlsResourceURL, control.deviation, err)
	}
	defer resp.Body.Close()

	// Truncate the external response body before emitting it into (public) CI logs. Every marker
	// sits in the first ~100 bytes of the resource's error envelope, well inside this limit.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	if resp.StatusCode == http.StatusOK {
		t.Fatalf("the resource returned HTTP 200 for an mtls_pop token even though %s. Exactly one thing "+
			"differs between this call and the positive call, so a 200 here means the resource does not "+
			"enforce that part of the binding contract at all, which means the HTTP 200 in "+
			"requireTokenAcceptedByResource proves only that the token was accepted, not that "+
			"proof-of-possession was checked. Response: %s", control.deviation, string(body))
	}
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected the resource to reject the call with HTTP 401 or 403 when %s, got HTTP %d. An "+
			"unexpected status means the call never reached the mTLS enforcement path, so this negative "+
			"control is not proving anything and needs to be re-verified against the resource. "+
			"Response: %s", control.deviation, resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), control.wantMarker) {
		t.Fatalf("the resource rejected the call with HTTP %d when %s, but the response does not contain "+
			"%q, so the rejection cannot be attributed to that deviation - an expired or malformed token, "+
			"or a rejection for one of the other binding failures, would look the same from here. "+
			"Response: %s", resp.StatusCode, control.deviation, control.wantMarker, string(body))
	}
}

// newUnrelatedClientCert builds a throwaway self-signed client certificate for the
// wrong-certificate negative control. It is generated in-process rather than provisioned from the
// lab: the control only needs some certificate the token is *not* bound to, so a second lab
// certificate would add a deployment dependency for no additional proof. It does not need to chain
// to a CA the resource trusts either, because the resource rejects it at the application layer on
// the cnf claim rather than at the TLS layer.
func newUnrelatedClientCert(t *testing.T) *tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the unrelated client certificate's key failed: %s", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "msal-go-unrelated-client-cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the unrelated client certificate failed: %s", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the unrelated client certificate failed: %s", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// TestCredential_X509_Output_Pop is the SNI X509 -> mtls_pop end-to-end test on the global endpoint.
// It uses the lab SN/I certificate (provisioned by the pipelines as cert.pem) as the client TLS
// certificate to obtain a Graph-scoped, certificate-bound mtls_pop token, verifies the token type and
// public binding certificate, then calls Microsoft Graph over mTLS with that certificate to prove the
// token is actually accepted by a resource (HTTP 200). It then replays that same call three times -
// without the certificate, under the Bearer scheme, and with an unrelated certificate - to prove the
// resource is genuinely enforcing the binding rather than ignoring client certificates. A second
// call must be served from the cache. Mirrors MSAL .NET's Credential_X509_Output_Pop.
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

	// The 200 above proves the token is accepted, not that the binding is enforced. Replay that same
	// call three times, each changing exactly one thing, and require a rejection that names the
	// thing that changed. Together they close the three ways the resource could be lenient:
	// ignoring client certificates entirely, honouring a cnf-bound token under a scheme that
	// carries no proof-of-possession, and accepting any certificate rather than the bound one.
	//
	// These live on this test only: enforcement is a property of the resource, not of each
	// acquisition path, so repeating them on the other cells would spend extra round trips for no
	// additional proof. All three reuse the token acquired above, for the same reason.
	requireTokenRejectedByResource(t, result.AccessToken, mtlsNegativeControl{
		deviation:  "no client certificate was presented on the TLS handshake",
		scheme:     "mtls_pop",
		clientCert: nil,
		wantMarker: mtlsMissingCertMarker,
	})
	requireTokenRejectedByResource(t, result.AccessToken, mtlsNegativeControl{
		deviation:  `the Authorization scheme was "Bearer" rather than "mtls_pop"`,
		scheme:     "Bearer",
		clientCert: result.BindingCertificate,
		wantMarker: mtlsWrongSchemeMarker,
	})
	requireTokenRejectedByResource(t, result.AccessToken, mtlsNegativeControl{
		deviation:  "a client certificate other than the token's binding certificate was presented",
		scheme:     "mtls_pop",
		clientCert: newUnrelatedClientCert(t),
		wantMarker: mtlsWrongCertMarker,
	})

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
