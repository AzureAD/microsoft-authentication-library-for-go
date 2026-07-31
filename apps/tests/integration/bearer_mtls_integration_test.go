// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
)

// bomUserFlowE2EEnv gates the Bearer-over-mTLS user-flow LIVE-ACQUIRE cells. The OBO/refresh/auth-code
// apps are not mTLS-enabled, so a live acquisition fails with AADSTS700027/AADSTS392189 (the same class
// of block as the two-leg FIC AADSTS51000). The wire contract for those flows is proven by the mocked
// unit tests in apps/confidential/confidential_bearer_mtls_test.go and by the request-capture cells
// below; the live cells are opt-in for when the apps are eventually enabled.
const bomUserFlowE2EEnv = "MSAL_RUN_BOM_USERFLOW_E2E"

// recordingMtlsClient wraps a real mTLS HTTP client so the Bearer-over-mTLS integration cells can assert
// on the outgoing token request (endpoint + form body) while still exercising the real transport. It
// records the request URL and parsed form BEFORE forwarding, so the captured values are available even
// when ESTS rejects the call (as it does for user flows on apps that are not yet mTLS-enabled). Mirrors
// MSAL .NET's RecordingMtlsHttpClientFactory.
type recordingMtlsClient struct {
	inner    ops.HTTPClient
	lastURL  *url.URL
	lastForm url.Values
}

func (c *recordingMtlsClient) Do(req *http.Request) (*http.Response, error) {
	c.lastURL = req.URL
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		c.lastForm, _ = url.ParseQuery(string(body))
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	return c.inner.Do(req)
}

func (c *recordingMtlsClient) CloseIdleConnections() {
	if c.inner != nil {
		c.inner.CloseIdleConnections()
	}
}

// recordingMtlsFactory returns a WithMtlsHTTPClient factory that presents the SN/I certificate on the TLS
// handshake (as Bearer-over-mTLS requires) and records every request into rec.
func recordingMtlsFactory(rec *recordingMtlsClient) func(cert tls.Certificate) ops.HTTPClient {
	return func(cert tls.Certificate) ops.HTTPClient {
		rec.inner = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
				},
			},
		}
		return rec
	}
}

// assertBearerOverMtlsRequest fails unless the captured token request routed to an mtlsauth endpoint and
// carried a private_key_jwt client_assertion, and did NOT request mtls_pop. This is the invariant of
// every Bearer-over-mTLS flow: the certificate authenticates the transport, the token stays Bearer.
func assertBearerOverMtlsRequest(t *testing.T, rec *recordingMtlsClient, wantGrant string) {
	t.Helper()
	if rec.lastURL == nil {
		t.Fatal("token endpoint was never called; the request was not routed over the mTLS transport")
	}
	if !strings.Contains(rec.lastURL.Host, "mtlsauth") {
		t.Errorf("token endpoint host = %q, want an mtlsauth.* host", rec.lastURL.Host)
	}
	if got := rec.lastForm.Get("grant_type"); got != wantGrant {
		t.Errorf("grant_type = %q, want %q", got, wantGrant)
	}
	if got := rec.lastForm.Get("client_assertion"); got == "" {
		t.Error("Bearer-over-mTLS must send a private_key_jwt client_assertion")
	}
	if got := rec.lastForm.Get("client_assertion_type"); !strings.Contains(got, "jwt-bearer") {
		t.Errorf("client_assertion_type = %q, want jwt-bearer (not jwt-pop)", got)
	}
	if got := rec.lastForm.Get("token_type"); got == "mtls_pop" {
		t.Error("Bearer-over-mTLS must not request token_type=mtls_pop")
	}
	if rec.lastForm.Get("req_cnf") != "" {
		t.Error("Bearer-over-mTLS request must not send req_cnf")
	}
}

// TestSendCertificateOverMtls_ClientCredential_Live is the Bearer-over-mTLS client-credentials E2E on the
// allow-listed SN/I app. WithSendCertificateOverMtls presents the certificate on the TLS handshake to the
// mtlsauth endpoint and ESTS returns a PLAIN Bearer access token (NOT certificate-bound), which a normal
// Bearer cache lookup must return on the second call. This is the whole point of the feature: the cert
// authenticates the transport, the token is an ordinary Bearer with a standard (not thumbprint-fenced)
// cache key. Mirrors MSAL .NET's ClientCredentialsMtlsPopTests.Sni_Over_Mtls_Gets_Bearer_Token_Successfully.
func TestSendCertificateOverMtls_ClientCredential_Live(t *testing.T) {
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

	rec := &recordingMtlsClient{}
	// Region westus3 + the Key Vault scope is the allow-listed client-credentials configuration for live
	// mTLS acquisition; the flag routes it to the regional mtlsauth endpoint.
	app, err := confidential.New(sniAllowlistedAuthority, sniAllowlistedAppID, cred,
		confidential.WithSendCertificateOverMtls(),
		confidential.WithAzureRegion(sniAllowlistedRegion),
		confidential.WithMtlsHTTPClient(recordingMtlsFactory(rec)),
	)
	if err != nil {
		t.Fatalf("confidential.New() failed: %s", errors.Verbose(err))
	}

	ctx := context.Background()
	scopes := []string{mtlsPoPResourceScope}

	result, err := app.AcquireTokenByCredential(ctx, scopes)
	if err != nil {
		t.Fatalf("AcquireTokenByCredential() (Bearer-over-mTLS) failed: %s", errors.Verbose(err))
	}
	if result.AccessToken == "" {
		t.Fatal("AcquireTokenByCredential() returned empty AccessToken")
	}
	if result.Metadata.TokenType != "Bearer" {
		t.Fatalf("expected token_type Bearer, got %q", result.Metadata.TokenType)
	}
	if result.BindingCertificate != nil {
		t.Fatal("Bearer-over-mTLS must not certificate-bind the token; BindingCertificate should be nil")
	}
	assertBearerOverMtlsRequest(t, rec, "client_credentials")

	// The plain Bearer must be served from cache on the second call (standard key, not thumbprint-fenced).
	// This also guards the second-call regression: instance/region metadata must resolve against the
	// original login.* authority, not the rewritten mtlsauth host.
	cached, err := app.AcquireTokenByCredential(ctx, scopes)
	if err != nil {
		t.Fatalf("second AcquireTokenByCredential() failed: %s", errors.Verbose(err))
	}
	if cached.Metadata.TokenSource != confidential.TokenSourceCache {
		t.Fatal("second AcquireTokenByCredential() did not return the token from cache")
	}
	if cached.AccessToken != result.AccessToken {
		t.Fatal("cached token does not match the originally issued token")
	}
}

// TestSendCertificateOverMtls_OnBehalfOf_RequestCapture proves the OBO flow builds and sends a
// Bearer-over-mTLS token request even though the OBO app is not mTLS-enabled (ESTS rejects the call with
// an AADSTS error). The recording transport captures the request before forwarding, so the endpoint and
// body are asserted while the service rejection is tolerated. Mirrors MSAL .NET's request-capture cells
// in MtlsTransportUserFlowTests (RecordingMtlsHttpClientFactory + tolerated service exception).
func TestSendCertificateOverMtls_OnBehalfOf_RequestCapture(t *testing.T) {
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

	rec := &recordingMtlsClient{}
	app, err := confidential.New(sniAllowlistedAuthority, sniAllowlistedAppID, cred,
		confidential.WithSendCertificateOverMtls(),
		confidential.WithMtlsHTTPClient(recordingMtlsFactory(rec)),
	)
	if err != nil {
		t.Fatalf("confidential.New() failed: %s", errors.Verbose(err))
	}

	// A fake user assertion is sufficient: ESTS rejects it, but MSAL still constructs and sends the OBO
	// token request over the mTLS transport, which is what this cell asserts.
	_, err = app.AcquireTokenOnBehalfOf(context.Background(), "fake-user-assertion-for-request-capture", []string{mtlsPoPResourceScope})
	if err != nil {
		t.Logf("tolerated expected OBO service rejection (app not mTLS-enabled): %s", err)
	}
	assertBearerOverMtlsRequest(t, rec, "urn:ietf:params:oauth:grant-type:jwt-bearer")
	if got := rec.lastForm.Get("requested_token_use"); got != "on_behalf_of" {
		t.Errorf("requested_token_use = %q, want on_behalf_of", got)
	}
}

// TestSendCertificateOverMtls_AuthCode_RequestCapture proves the authorization-code redemption builds and
// sends a Bearer-over-mTLS token request. As with OBO, the code is rejected by ESTS but the request is
// captured and asserted before forwarding. Mirrors MSAL .NET's auth-code request-capture cell.
func TestSendCertificateOverMtls_AuthCode_RequestCapture(t *testing.T) {
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

	rec := &recordingMtlsClient{}
	app, err := confidential.New(sniAllowlistedAuthority, sniAllowlistedAppID, cred,
		confidential.WithSendCertificateOverMtls(),
		confidential.WithMtlsHTTPClient(recordingMtlsFactory(rec)),
	)
	if err != nil {
		t.Fatalf("confidential.New() failed: %s", errors.Verbose(err))
	}

	_, err = app.AcquireTokenByAuthCode(context.Background(), "fake-auth-code-for-request-capture", "https://localhost/redirect", []string{mtlsPoPResourceScope})
	if err != nil {
		t.Logf("tolerated expected auth-code service rejection (app not mTLS-enabled): %s", err)
	}
	assertBearerOverMtlsRequest(t, rec, "authorization_code")
}

// TestSendCertificateOverMtls_OnBehalfOf_Live is the LIVE-ACQUIRE OBO variant. It is skip-gated because
// the OBO app is not mTLS-enabled, so a live acquisition fails with AADSTS700027/AADSTS392189 (pending
// app mTLS-enablement) — the same class of block that skip-gates the two-leg FIC E2E. Enable it with
// MSAL_RUN_BOM_USERFLOW_E2E once the app is provisioned. The wire contract is otherwise covered by the
// request-capture cell above and the mocked unit tests.
func TestSendCertificateOverMtls_OnBehalfOf_Live(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	if os.Getenv(bomUserFlowE2EEnv) == "" {
		t.Skipf("skipping live Bearer-over-mTLS OBO acquisition: set %s to run (pending app mTLS-enablement, AADSTS700027/392189)", bomUserFlowE2EEnv)
	}

	cert, privateKey, err := getCertDataFromFile(pemFile)
	if err != nil {
		t.Fatalf("getCertDataFromFile() failed: %s", errors.Verbose(err))
	}
	cred, err := confidential.NewCredFromCert(cert, privateKey)
	if err != nil {
		t.Fatalf("NewCredFromCert() failed: %s", errors.Verbose(err))
	}

	app, err := confidential.New(sniAllowlistedAuthority, sniAllowlistedAppID, cred, confidential.WithSendCertificateOverMtls())
	if err != nil {
		t.Fatalf("confidential.New() failed: %s", errors.Verbose(err))
	}

	userAssertion := os.Getenv("MSAL_BOM_OBO_USER_ASSERTION")
	if userAssertion == "" {
		t.Fatalf("%s is set but MSAL_BOM_OBO_USER_ASSERTION (a real user token) is required for the live OBO acquisition", bomUserFlowE2EEnv)
	}

	result, err := app.AcquireTokenOnBehalfOf(context.Background(), userAssertion, []string{mtlsPoPResourceScope})
	if err != nil {
		t.Fatalf("AcquireTokenOnBehalfOf() (Bearer-over-mTLS) failed: %s", errors.Verbose(err))
	}
	if result.Metadata.TokenType != "Bearer" {
		t.Fatalf("expected token_type Bearer, got %q", result.Metadata.TokenType)
	}
	if result.BindingCertificate != nil {
		t.Fatal("Bearer-over-mTLS must not certificate-bind the token; BindingCertificate should be nil")
	}
}

// TestSendCertificateOverMtls_RefreshViaSilent_Live is the LIVE-ACQUIRE refresh variant. msal-go has no
// public refresh entrypoint, so refresh is exercised through AcquireTokenSilent (seeded refresh token ->
// refresh_token grant). It is doubly skip-gated: the refresh app is not mTLS-enabled (AADSTS700027/
// 392189), and a live refresh token can only be seeded after a successful interactive/auth-code login,
// which the lab cannot perform here. The refresh-over-mtlsauth wire contract is proven deterministically
// by the mocked unit test TestSendCertificateOverMtls_RefreshViaSilent.
func TestSendCertificateOverMtls_RefreshViaSilent_Live(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	t.Skipf("skipping live Bearer-over-mTLS refresh acquisition: requires a seeded refresh token AND app mTLS-enablement (AADSTS700027/392189); wire contract is unit-covered by TestSendCertificateOverMtls_RefreshViaSilent")
}
