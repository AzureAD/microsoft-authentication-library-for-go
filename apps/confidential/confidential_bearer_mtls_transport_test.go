// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	msalerrors "github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

// The tests in this file deliberately do NOT use WithMtlsHTTPClient. Substituting the mTLS client is
// the documented escape hatch, and a test that uses it never exercises the transport a real caller
// gets. Everything here runs on MSAL's built-in mTLS transport (comm.BuildMtlsClient) across a real
// TLS 1.2+ handshake against a local server, so a regression in certificate injection or in the
// cloning of the application's own transport fails the build instead of only failing in production.

// mtlsTestPKI is a throwaway certificate authority plus a server certificate valid for the AAD hosts
// a Bearer-over-mTLS acquisition talks to. Using a real CA rather than InsecureSkipVerify matters:
// RootCAs lives on the application's *tls.Config, so if MSAL ever stops cloning the configured
// transport, verification fails and these tests break.
type mtlsTestPKI struct {
	roots      *x509.CertPool
	serverCert tls.Certificate
}

func newMtlsTestPKI(t *testing.T, hosts ...string) mtlsTestPKI {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the test CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "msal-go mTLS test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating the test CA certificate: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parsing the test CA certificate: %v", err)
	}

	srvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the test server key: %v", err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     hosts,
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, ca, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating the test server certificate: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return mtlsTestPKI{
		roots:      roots,
		serverCert: tls.Certificate{Certificate: [][]byte{srvDER, caDER}, PrivateKey: srvKey},
	}
}

// mtlsTestServer impersonates login.microsoftonline.com and mtlsauth.microsoft.com on a local TLS
// listener. It requests (but does not require) a client certificate, so the token endpoint can report
// exactly what the caller presented on the handshake instead of merely failing the connection.
type mtlsTestServer struct {
	host        string
	tenant      string
	tokenStatus int
	tokenBody   []byte

	mu         sync.Mutex
	tokenCalls int
	tokenHost  string
	tokenForm  url.Values
	peerCerts  [][]byte
}

func (s *mtlsTestServer) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.Contains(r.URL.Path, "/discovery/instance"):
		s.writeJSON(w, http.StatusOK, mock.GetInstanceDiscoveryBody(s.host, s.tenant))
	case strings.Contains(r.URL.Path, "/.well-known/openid-configuration"):
		s.writeJSON(w, http.StatusOK, mock.GetTenantDiscoveryBody(s.host, s.tenant))
	case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
		body, err := io.ReadAll(r.Body)
		if err != nil {
			s.writeJSON(w, http.StatusInternalServerError, []byte(`{"error":"read_failed"}`))
			return
		}
		form, _ := url.ParseQuery(string(body))

		var peers [][]byte
		if r.TLS != nil {
			for _, c := range r.TLS.PeerCertificates {
				peers = append(peers, c.Raw)
			}
		}

		s.mu.Lock()
		s.tokenCalls++
		s.tokenHost = r.Host
		s.tokenForm = form
		s.peerCerts = peers
		status, respBody := s.tokenStatus, s.tokenBody
		s.mu.Unlock()

		s.writeJSON(w, status, respBody)
	default:
		http.NotFound(w, r)
	}
}

func (s *mtlsTestServer) writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *mtlsTestServer) snapshot() (calls int, host string, form url.Values, peers [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenCalls, s.tokenHost, s.tokenForm, s.peerCerts
}

// start brings up the listener and returns the *http.Client an application would pass to
// WithHTTPClient. Its transport is an ordinary *http.Transport carrying the settings a real
// deployment would care about (a custom dialer and a custom root pool). MSAL must clone that
// transport for the mTLS token request, so both settings have to survive into the mTLS connection or
// nothing here resolves or verifies.
func (s *mtlsTestServer) start(t *testing.T) *http.Client {
	t.Helper()

	pki := newMtlsTestPKI(t, s.host, mtlsGlobalHost)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	addr := srv.Listener.Addr().String()
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			// Every AAD hostname resolves to the local listener. TLS still verifies the name from
			// the URL against the server certificate, so the hosts MSAL routes to are real
			// assertions, not just recorded strings.
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{RootCAs: pki.roots, MinVersion: tls.VersionTLS12},
		},
	}
}

// mtlsGlobalHost is the endpoint Bearer-over-mTLS rewrites token requests to when no region is set.
const mtlsGlobalHost = "mtlsauth.microsoft.com"

// TestSendCertificateOverMtls_DefaultTransportPresentsCertificate is the regression guard for the
// primary customer path: an application that only sets WithSendCertificateOverMtls, with no transport
// override of any kind, must have MSAL's built-in mTLS transport present the credential's certificate
// on the TLS handshake to the mtlsauth endpoint and hand back a plain, unbound ******
//
// Every other Bearer-over-mTLS unit test replaces the mTLS client with a mock and therefore proves
// nothing about the transport. This one performs a real handshake against a local server and asserts
// on the certificate the server actually received, so dropping the certificate injection in
// comm.BuildMtlsClient fails here. It also pins that the application's own transport survives:
// resolution goes through a custom dialer and verification through a custom root pool, both of which
// live on the configured transport and are reachable only if MSAL clones it.
func TestSendCertificateOverMtls_DefaultTransportPresentsCertificate(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}

	tenant := "tenant"
	lmo := "login.microsoftonline.com"
	srv := &mtlsTestServer{
		host:        lmo,
		tenant:      tenant,
		tokenStatus: http.StatusOK,
		tokenBody:   mock.GetAccessTokenBody("bearer-over-mtls-token", "", "", "", 3600, 0),
	}
	httpClient := srv.start(t)

	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(httpClient),
		WithSendCertificateOverMtls(),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	res, err := client.AcquireTokenByCredential(ctx, tokenScope)
	if err != nil {
		t.Fatalf("AcquireTokenByCredential() over the built-in mTLS transport failed: %s", msalerrors.Verbose(err))
	}

	calls, host, form, peers := srv.snapshot()
	if calls != 1 {
		t.Fatalf("token endpoint was called %d times, want 1", calls)
	}
	if host != mtlsGlobalHost {
		t.Errorf("token endpoint host = %q, want %s", host, mtlsGlobalHost)
	}

	// The point of the whole feature: the credential's certificate reached the server on the
	// handshake, without the application supplying any transport of its own.
	if len(peers) == 0 {
		t.Fatal("the built-in mTLS transport presented no client certificate on the TLS handshake")
	}
	var matched bool
	for _, der := range peers {
		if bytes.Equal(der, certs[0].Raw) {
			matched = true
			break
		}
	}
	if !matched {
		t.Error("the certificate presented on the TLS handshake is not the credential's certificate")
	}

	// The token stays Bearer: the certificate authenticates the transport, it does not bind the token.
	if got := form.Get("token_type"); got != "" {
		t.Errorf("token_type = %q, want empty (Bearer-over-mTLS must not request mtls_pop)", got)
	}
	if form.Get("req_cnf") != "" {
		t.Error("Bearer-over-mTLS request must not send req_cnf")
	}
	if got := form.Get("client_assertion"); got == "" {
		t.Error("Bearer-over-mTLS must send a private_key_jwt client_assertion")
	} else {
		assertClientAssertionHasX5C(t, got)
	}
	if res.Metadata.TokenType != "Bearer" {
		t.Errorf("Metadata.TokenType = %q, want Bearer", res.Metadata.TokenType)
	}
	if res.BindingCertificate != nil {
		t.Error("Bearer-over-mTLS token is not bound; BindingCertificate must be nil")
	}

	// A plain ****** goes in the standard cache, so the second call must not reach the network.
	res2, err := client.AcquireTokenByCredential(ctx, tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Metadata.TokenSource != TokenSourceCache {
		t.Errorf("second call TokenSource = %d, want cache", res2.Metadata.TokenSource)
	}
	if res2.AccessToken != res.AccessToken {
		t.Error("the cached token does not match the originally issued token")
	}
	if calls, _, _, _ := srv.snapshot(); calls != 1 {
		t.Errorf("token endpoint was called %d times after the cached call, want 1", calls)
	}
}

// TestSendCertificateOverMtls_DefaultTransportSurfacesRequestOnError pins the contract the live
// request-capture integration cells depend on. Those cells run against apps that are not yet
// mTLS-enabled, so the acquisition always ends in an AADSTS rejection and there is no result to
// assert on. Rather than substitute a recording client - which would stop exercising the transport
// under test - they read the outgoing request back off errors.CallErr.
//
// That only works if CallErr survives unwrapping and its Req still carries a replayable body, which
// is exactly what this test locks down, over the built-in mTLS transport and a real handshake.
func TestSendCertificateOverMtls_DefaultTransportSurfacesRequestOnError(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}

	tenant := "tenant"
	lmo := "login.microsoftonline.com"
	srv := &mtlsTestServer{
		host:        lmo,
		tenant:      tenant,
		tokenStatus: http.StatusBadRequest,
		tokenBody:   []byte(`{"error":"invalid_client","error_description":"AADSTS700027: mTLS is not enabled for this application."}`),
	}
	httpClient := srv.start(t)

	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(httpClient),
		WithSendCertificateOverMtls(),
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AcquireTokenByCredential(context.Background(), tokenScope)
	if err == nil {
		t.Fatal("expected the AADSTS rejection to surface as an error")
	}

	reqURL, form, capErr := capturedTokenRequest(err)
	if capErr != nil {
		t.Fatalf("could not recover the outgoing token request from the error: %v (error was: %s)", capErr, err)
	}
	if reqURL.Host != mtlsGlobalHost {
		t.Errorf("captured token endpoint host = %q, want %s", reqURL.Host, mtlsGlobalHost)
	}
	if got := form.Get("grant_type"); got != "client_credentials" {
		t.Errorf("captured grant_type = %q, want client_credentials", got)
	}
	if got := form.Get("client_assertion"); got == "" {
		t.Error("captured request carries no private_key_jwt client_assertion")
	}
	if got := form.Get("token_type"); got == "mtls_pop" {
		t.Error("captured request asked for mtls_pop; Bearer-over-mTLS must not")
	}

	// The certificate must be presented even on the failing call: the rejection is a service-side
	// policy decision, not a transport that quietly skipped the certificate.
	if _, _, _, peers := srv.snapshot(); len(peers) == 0 {
		t.Error("the built-in mTLS transport presented no client certificate on the rejected call")
	}
}

// capturedTokenRequest recovers the outgoing token request from an MSAL error. It mirrors the helper
// the Bearer-over-mTLS integration cells use; keeping a copy here means the technique is verified
// deterministically in CI rather than only on a live run.
func capturedTokenRequest(err error) (*url.URL, url.Values, error) {
	var callErr msalerrors.CallErr
	if !msalerrors.As(err, &callErr) || callErr.Req == nil {
		return nil, nil, fmt.Errorf("error does not carry an errors.CallErr with a request")
	}
	if callErr.Req.GetBody == nil {
		return nil, nil, fmt.Errorf("the captured request has no replayable body")
	}
	body, err := callErr.Req.GetBody()
	if err != nil {
		return nil, nil, fmt.Errorf("replaying the captured request body: %w", err)
	}
	defer body.Close()
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, nil, fmt.Errorf("reading the captured request body: %w", err)
	}
	form, err := url.ParseQuery(string(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing the captured request body: %w", err)
	}
	return callErr.Req.URL, form, nil
}
