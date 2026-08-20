// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

// newSelfSignedCert mints a throwaway RSA certificate. key is returned separately so tests can wrap
// it in an opaque signer.
func newSelfSignedCert(t *testing.T, commonName string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, key
}

// tlsCertFor bundles a leaf and a key the way AuthResult.BindingCertificate does: DER chain, parsed
// leaf, and a private key that is only ever used as a crypto.Signer.
func tlsCertFor(leaf *x509.Certificate, key crypto.PrivateKey) *tls.Certificate {
	return &tls.Certificate{
		Certificate: [][]byte{leaf.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

// mtlsHandshakeServer is an httptest TLS server that requires a client certificate and records the
// one actually presented on each handshake, so tests can assert on the real TLS layer instead of
// trusting a mock.
type mtlsHandshakeServer struct {
	srv *httptest.Server

	mu    sync.Mutex
	certs []*x509.Certificate
	forms []url.Values
	hosts []string
}

func newMtlsHandshakeServer(t *testing.T, body []byte) *mtlsHandshakeServer {
	t.Helper()
	s := &mtlsHandshakeServer{}
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		var presented *x509.Certificate
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			presented = r.TLS.PeerCertificates[0]
		}
		s.mu.Lock()
		s.certs = append(s.certs, presented)
		s.forms = append(s.forms, form)
		s.hosts = append(s.hosts, r.Host)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	s.srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	return s
}

// clientFactory returns a WithMtlsHTTPClient factory that builds a real mTLS client from the
// certificate MSAL hands it and routes every request to the test server regardless of the URL's host.
// The certificate is taken from the factory argument (never captured from the test) so the handshake
// proves which certificate MSAL selected.
func (s *mtlsHandshakeServer) clientFactory() func(tls.Certificate) *http.Client {
	addr := s.srv.Listener.Addr().String()
	return func(cert tls.Certificate) *http.Client {
		return &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				},
				TLSClientConfig: &tls.Config{
					//nolint:gosec // the test server uses an ephemeral self-signed certificate
					InsecureSkipVerify: true,
					MinVersion:         tls.VersionTLS12,
					Certificates:       []tls.Certificate{cert},
				},
			},
		}
	}
}

func (s *mtlsHandshakeServer) presented(t *testing.T) *x509.Certificate {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.certs) != 1 {
		t.Fatalf("token endpoint was called %d times, want exactly 1", len(s.certs))
	}
	if s.certs[0] == nil {
		t.Fatal("no client certificate was presented on the TLS handshake")
	}
	return s.certs[0]
}

func (s *mtlsHandshakeServer) tokenCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.certs)
}

func (s *mtlsHandshakeServer) form(t *testing.T) url.Values {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.forms) == 0 {
		t.Fatal("token endpoint was never called")
	}
	return s.forms[0]
}

func (s *mtlsHandshakeServer) host(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.hosts) == 0 {
		t.Fatal("token endpoint was never called")
	}
	return s.hosts[0]
}

// discoveryClient answers instance- and tenant-discovery requests by URL rather than in a fixed
// order. Resolving the signed-assertion callback moves endpoint resolution ahead of the cache read,
// which reverses the order of the two discovery calls; routing by URL keeps the fixture from
// encoding an ordering that is incidental to what these tests are about.
type discoveryClient struct {
	host, tenant string
}

func (c discoveryClient) Do(req *http.Request) (*http.Response, error) {
	var body []byte
	switch {
	case strings.Contains(req.URL.Path, "/discovery/instance"):
		body = mock.GetInstanceDiscoveryBody(c.host, c.tenant)
	case strings.Contains(req.URL.Path, "openid-configuration"):
		body = mock.GetTenantDiscoveryBody(c.host, c.tenant)
	default:
		return nil, fmt.Errorf("unexpected non-mTLS request to %s", req.URL)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}, nil
}

func (discoveryClient) CloseIdleConnections() {}

// handshakeTestClient builds a confidential client whose discovery traffic is answered locally and
// whose mTLS token request performs a real TLS handshake against srv.
func handshakeTestClient(t *testing.T, cred Credential, srv *mtlsHandshakeServer) Client {
	t.Helper()
	tenant := "tenant"
	lmo := "login.microsoftonline.com"
	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(discoveryClient{host: lmo, tenant: tenant}),
		WithMtlsHTTPClient(srv.clientFactory()),
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// TestWithMtlsBindingTLSCertificateHandshake is the end-to-end proof for the *tls.Certificate
// overload: a leg-1 result is handed to leg 2 verbatim, and the certificate that reaches the TLS
// handshake is that exact certificate. The assertion is still sent as a certificate-bound (jwt-pop)
// client assertion.
func TestWithMtlsBindingTLSCertificateHandshake(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "leg1-binding-cert")
	leg1BindingCertificate := tlsCertFor(leaf, key)
	const assertion = "leg1-cert-bound-assertion"

	srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("final-mtls-token", 3600))
	cred := NewCredFromAssertionCallback(func(context.Context, AssertionRequestOptions) (string, error) {
		return assertion, nil
	})
	client := handshakeTestClient(t, cred, srv)

	res, err := client.AcquireTokenByCredential(context.Background(), tokenScope,
		WithMtlsProofOfPossession(WithMtlsBindingTLSCertificate(leg1BindingCertificate)))
	if err != nil {
		t.Fatal(err)
	}

	if got := srv.presented(t); !got.Equal(leaf) {
		t.Errorf("handshake presented %q, want the leg-1 binding certificate %q", got.Subject.CommonName, leaf.Subject.CommonName)
	}
	if got := srv.host(t); got != "mtlsauth.microsoft.com" {
		t.Errorf("token request Host = %q, want mtlsauth.microsoft.com", got)
	}
	body := srv.form(t)
	if got := body.Get("client_assertion"); got != assertion {
		t.Errorf("client_assertion = %q, want %q", got, assertion)
	}
	if got := body.Get("client_assertion_type"); got != "urn:ietf:params:oauth:client-assertion-type:jwt-pop" {
		t.Errorf("client_assertion_type = %q, want the jwt-pop value", got)
	}
	if got := body.Get("token_type"); got != "mtls_pop" {
		t.Errorf("token_type = %q, want mtls_pop", got)
	}
	if res.Metadata.TokenType != "mtls_pop" {
		t.Errorf("Metadata.TokenType = %q, want mtls_pop", res.Metadata.TokenType)
	}
	if res.BindingCertificate == nil || res.BindingCertificate.Leaf == nil || !res.BindingCertificate.Leaf.Equal(leaf) {
		t.Error("AuthResult.BindingCertificate is not the certificate the token was bound to")
	}
}

// TestWithMtlsBindingTLSCertificateCopiesInput proves MSAL doesn't retain the caller's struct.
// Mutating the caller's tls.Certificate after the option is built must not change what MSAL uses:
// the same value is retained by the per-thumbprint mTLS client cache and handed back on AuthResult,
// so sharing it would race with concurrent acquisitions (a -race run caught exactly that before).
func TestWithMtlsBindingTLSCertificateCopiesInput(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "original-binding-cert")
	other, _ := newSelfSignedCert(t, "swapped-in-binding-cert")
	caller := tlsCertFor(leaf, key)

	srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("final-mtls-token", 3600))
	cred := NewCredFromAssertionCallback(func(context.Context, AssertionRequestOptions) (string, error) {
		return "assertion", nil
	})
	client := handshakeTestClient(t, cred, srv)

	opt := WithMtlsProofOfPossession(WithMtlsBindingTLSCertificate(caller))

	// The application reuses its struct for the next rotation while the previous acquisition is
	// still in flight. MSAL must be unaffected.
	caller.Certificate[0] = other.Raw
	caller.Leaf = other

	if _, err := client.AcquireTokenByCredential(context.Background(), tokenScope, opt); err != nil {
		t.Fatal(err)
	}
	if got := srv.presented(t); !got.Equal(leaf) {
		t.Errorf("handshake presented %q, want %q: MSAL retained the caller's struct instead of copying it",
			got.Subject.CommonName, leaf.Subject.CommonName)
	}
}

// TestWithMtlsBindingTLSCertificateRejectsUnusableCerts covers the guardrails: a certificate that
// can't complete a handshake must fail with a clear error before any network call, not panic and not
// produce a broken handshake.
func TestWithMtlsBindingTLSCertificateRejectsUnusableCerts(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "binding-cert")
	other, otherKey := newSelfSignedCert(t, "unrelated-cert")
	for _, test := range []struct {
		name string
		cert *tls.Certificate
		want string
	}{
		{"nil certificate", nil, "is nil"},
		{"nil chain", &tls.Certificate{PrivateKey: key}, "no certificate chain"},
		{"empty chain", &tls.Certificate{Certificate: [][]byte{}, PrivateKey: key}, "no certificate chain"},
		{"empty leaf entry", &tls.Certificate{Certificate: [][]byte{{}}, PrivateKey: key}, "no certificate chain"},
		{"nil private key", &tls.Certificate{Certificate: [][]byte{leaf.Raw}, Leaf: leaf}, "no private key"},
		{"key is not a signer", &tls.Certificate{Certificate: [][]byte{leaf.Raw}, Leaf: leaf, PrivateKey: "not-a-key"}, "crypto.Signer"},
		{"unparsable leaf", &tls.Certificate{Certificate: [][]byte{[]byte("not DER")}, PrivateKey: key}, "could not be parsed"},
		// The key belongs to a different certificate. Without a public-key comparison this passes
		// local validation and fails much later as an opaque TLS handshake error from the server.
		{"key does not match the certificate", &tls.Certificate{Certificate: [][]byte{leaf.Raw}, Leaf: leaf, PrivateKey: otherKey}, "does not match the public key"},
		// Leaf names a different certificate than the one that would be presented. MSAL takes the
		// cache-partitioning x5t#S256 from Leaf and the wire certificate from Certificate[0], so
		// tolerating this binds the token to one certificate and keys it under another. It also
		// makes Leaf useless as the source of truth for the key comparison above: here the key
		// matches Leaf but not Certificate[0].
		{"Leaf disagrees with Certificate[0]", &tls.Certificate{Certificate: [][]byte{leaf.Raw}, Leaf: other, PrivateKey: otherKey}, "Leaf is not the certificate in Certificate[0]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			certs, credKey := loadTestCert(t)
			cred, err := NewCredFromCert(certs, credKey)
			if err != nil {
				t.Fatal(err)
			}
			// A certificate credential could supply a binding certificate on its own, so if the
			// option's error were dropped the call would succeed with the wrong certificate.
			client, _ := mtlsPoPTestClient(t, cred)
			_, err = client.AcquireTokenByCredential(context.Background(), tokenScope,
				WithMtlsProofOfPossession(WithMtlsBindingTLSCertificate(test.cert)))
			if err == nil {
				t.Fatal("expected an error, got none")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error %q does not explain the problem (want it to mention %q)", err, test.want)
			}
			if !strings.Contains(err.Error(), "WithMtlsBindingTLSCertificate") {
				t.Errorf("error %q does not name the option at fault", err)
			}
		})
	}
}

// TestWithMtlsBindingTLSCertificateAcceptsUnparsedLeaf covers a certificate assembled by hand with
// no Leaf: MSAL needs the leaf for the x5t#S256 that partitions the cache, so it must parse it
// rather than dereference nil.
func TestWithMtlsBindingTLSCertificateAcceptsUnparsedLeaf(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "leaf-less-binding-cert")
	srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("final-mtls-token", 3600))
	cred := NewCredFromAssertionCallback(func(context.Context, AssertionRequestOptions) (string, error) {
		return "assertion", nil
	})
	client := handshakeTestClient(t, cred, srv)

	res, err := client.AcquireTokenByCredential(context.Background(), tokenScope,
		WithMtlsProofOfPossession(WithMtlsBindingTLSCertificate(&tls.Certificate{
			Certificate: [][]byte{leaf.Raw},
			PrivateKey:  key,
		})))
	if err != nil {
		t.Fatal(err)
	}
	if got := srv.presented(t); !got.Equal(leaf) {
		t.Error("handshake did not present the supplied certificate")
	}
	if res.BindingCertificate == nil || res.BindingCertificate.Leaf == nil {
		t.Fatal("AuthResult.BindingCertificate.Leaf is nil; MSAL did not parse the leaf")
	}
	if !res.BindingCertificate.Leaf.Equal(leaf) {
		t.Error("AuthResult.BindingCertificate.Leaf is not the supplied certificate")
	}
}

// TestValidBindingCertificateDeepCopiesDER pins the copy depth. Copying only the outer [][]byte
// leaves every DER entry's backing array shared with the caller, so an application that reuses its
// buffers can rewrite the certificate MSAL has retained — and race with an in-flight acquisition on
// it, since the same value is held in the per-thumbprint mTLS client cache and handed back on
// AuthResult.
//
// The mutation is deliberately made *inside* existing entries rather than by replacing an entry: the
// outer copy alone already defends against replacement, so a replacement test would pass without a
// deep copy and prove nothing.
func TestValidBindingCertificateDeepCopiesDER(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "deep-copy-binding-cert")
	intermediate, _ := newSelfSignedCert(t, "deep-copy-intermediate")
	wantLeafDER := append([]byte(nil), leaf.Raw...)
	wantIntermediateDER := append([]byte(nil), intermediate.Raw...)
	caller := &tls.Certificate{
		Certificate: [][]byte{append([]byte(nil), leaf.Raw...), append([]byte(nil), intermediate.Raw...)},
		PrivateKey:  key,
	}

	retained, err := validBindingCertificate(caller)
	if err != nil {
		t.Fatal(err)
	}

	caller.Certificate[0][0] ^= 0xFF
	caller.Certificate[1][0] ^= 0xFF

	// Guard against a vacuous pass: if the writes above didn't change anything, the comparisons
	// below succeed no matter how shallow the copy is.
	if bytes.Equal(caller.Certificate[0], wantLeafDER) || bytes.Equal(caller.Certificate[1], wantIntermediateDER) {
		t.Fatal("the test did not actually mutate the caller's DER bytes, so it proves nothing")
	}
	if !bytes.Equal(retained.Certificate[0], wantLeafDER) {
		t.Error("mutating bytes in the caller's leaf entry changed the certificate MSAL retained")
	}
	if !bytes.Equal(retained.Certificate[1], wantIntermediateDER) {
		t.Error("mutating bytes in the caller's intermediate entry changed the certificate MSAL retained: entries beyond the leaf are still shared")
	}
}

// TestWithMtlsBindingTLSCertificateDeepCopiesDER is the end-to-end half of the property above: the
// deep copy is what actually reaches the TLS handshake. If the DER were shared, corrupting it after
// the option is built either presents a different certificate or fails the handshake outright.
func TestWithMtlsBindingTLSCertificateDeepCopiesDER(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "in-place-mutated-binding-cert")
	// tlsCertFor aliases leaf.Raw; copy it so the mutation below can't corrupt the certificate the
	// assertion compares against.
	caller := &tls.Certificate{Certificate: [][]byte{append([]byte(nil), leaf.Raw...)}, PrivateKey: key, Leaf: leaf}

	srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("final-mtls-token", 3600))
	cred := NewCredFromAssertionCallback(func(context.Context, AssertionRequestOptions) (string, error) {
		return "assertion", nil
	})
	client := handshakeTestClient(t, cred, srv)

	opt := WithMtlsProofOfPossession(WithMtlsBindingTLSCertificate(caller))
	caller.Certificate[0][0] ^= 0xFF

	if _, err := client.AcquireTokenByCredential(context.Background(), tokenScope, opt); err != nil {
		t.Fatalf("MSAL presented DER the caller mutated after the option was built: %v", err)
	}
	if got := srv.presented(t); !got.Equal(leaf) {
		t.Errorf("handshake presented %q, want the original certificate", got.Subject.CommonName)
	}
}

// TestSignedAssertionCallbackMismatchedKeyRejected is the callback-path counterpart of the
// "key does not match the certificate" case in TestWithMtlsBindingTLSCertificateRejectsUnusableCerts.
// A callback that pairs a certificate with the wrong key must be rejected with an error naming the
// callback, before any handshake, rather than surfacing as an opaque TLS error from the server.
func TestSignedAssertionCallbackMismatchedKeyRejected(t *testing.T) {
	leaf, _ := newSelfSignedCert(t, "mismatched-binding-cert")
	_, otherKey := newSelfSignedCert(t, "unrelated-key-holder")
	srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("unused", 3600))
	cred := NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
		return SignedAssertion{
			Assertion:          "assertion",
			BindingCertificate: &tls.Certificate{Certificate: [][]byte{leaf.Raw}, Leaf: leaf, PrivateKey: otherKey},
		}, nil
	})
	client := handshakeTestClient(t, cred, srv)

	_, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("a binding certificate whose key doesn't match it must be rejected")
	}
	if !strings.Contains(err.Error(), "signed-assertion callback") || !strings.Contains(err.Error(), "does not match the public key") {
		t.Errorf("error %q does not identify the callback's mismatched key as the problem", err)
	}
	if got := srv.tokenCalls(); got != 0 {
		t.Errorf("token endpoint called %d times, want 0: the mismatch must be caught before the handshake", got)
	}
}

// TestWithMtlsBindingTLSCertificateAcceptsECDSAKey is the control for the key/certificate comparison:
// it must not have narrowed the accepted key types. newTLSBindingCertificate compares RSA moduli
// directly, which would reject every non-RSA key; validBindingCertificate compares through the Equal
// method that all standard-library public key types implement, so an ECDSA binding certificate
// completes a real handshake. This matters beyond ECDSA — the same code path carries opaque
// KeyGuard/CNG/HSM signers, whose concrete key type MSAL never sees.
func TestWithMtlsBindingTLSCertificateAcceptsECDSAKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "ecdsa-binding-cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("final-mtls-token", 3600))
	cred := NewCredFromAssertionCallback(func(context.Context, AssertionRequestOptions) (string, error) {
		return "assertion", nil
	})
	client := handshakeTestClient(t, cred, srv)

	if _, err := client.AcquireTokenByCredential(context.Background(), tokenScope,
		WithMtlsProofOfPossession(WithMtlsBindingTLSCertificate(tlsCertFor(leaf, key)))); err != nil {
		t.Fatalf("an ECDSA binding certificate was rejected: %v", err)
	}
	if got := srv.presented(t); !got.Equal(leaf) {
		t.Error("handshake did not present the ECDSA binding certificate")
	}
}

// TestSignedAssertionCallbackHandshake is the core test for the signed-assertion credential: one
// callback returns the assertion and its binding certificate, and both reach the wire together —
// the certificate on the TLS handshake, the assertion in the certificate-bound request body.
func TestSignedAssertionCallbackHandshake(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "callback-binding-cert")
	const assertion = "callback-assertion"
	srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("final-mtls-token", 3600))

	cred := NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
		return SignedAssertion{Assertion: assertion, BindingCertificate: tlsCertFor(leaf, key)}, nil
	})
	client := handshakeTestClient(t, cred, srv)

	res, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}

	if got := srv.presented(t); !got.Equal(leaf) {
		t.Errorf("handshake presented %q, want the callback's certificate %q", got.Subject.CommonName, leaf.Subject.CommonName)
	}
	if got := srv.host(t); got != "mtlsauth.microsoft.com" {
		t.Errorf("token request Host = %q, want mtlsauth.microsoft.com", got)
	}
	body := srv.form(t)
	if got := body.Get("client_assertion"); got != assertion {
		t.Errorf("client_assertion = %q, want the callback's assertion %q", got, assertion)
	}
	if got := body.Get("client_assertion_type"); got != "urn:ietf:params:oauth:client-assertion-type:jwt-pop" {
		t.Errorf("client_assertion_type = %q, want the jwt-pop value", got)
	}
	if res.Metadata.TokenType != "mtls_pop" {
		t.Errorf("Metadata.TokenType = %q, want mtls_pop", res.Metadata.TokenType)
	}
	if res.BindingCertificate == nil || res.BindingCertificate.Leaf == nil || !res.BindingCertificate.Leaf.Equal(leaf) {
		t.Error("AuthResult.BindingCertificate is not the certificate the callback supplied")
	}
}

// TestSignedAssertionCallbackInvokedExactlyOnce is the hard requirement: the callback may perform
// FIC leg 1, a real network call that can be expensive, rate-limited, or non-idempotent. Resolving
// it early (the binding certificate is needed before the cache is read) must not turn into a second
// invocation when the request body is assembled.
func TestSignedAssertionCallbackInvokedExactlyOnce(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "once-binding-cert")
	var calls int32
	srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("final-mtls-token", 3600))

	cred := NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
		atomic.AddInt32(&calls, 1)
		return SignedAssertion{Assertion: "assertion", BindingCertificate: tlsCertFor(leaf, key)}, nil
	})
	client := handshakeTestClient(t, cred, srv)

	if _, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession()); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("callback invoked %d times during one acquisition, want exactly 1", got)
	}
	if got := srv.presented(t); !got.Equal(leaf) {
		t.Error("handshake did not present the callback's certificate")
	}
}

// TestSignedAssertionCallbackNotInvokedOnCacheHit pins the other half of the invocation contract: a
// token served from the cache must not pay for leg 1 again.
//
// The demonstration is a bearer request, because that is the only request that doesn't need the
// certificate: there the callback stays lazy exactly as NewCredFromAssertionCallback's does, so the
// cached second acquisition never reaches it. An mTLS proof-of-possession request cannot show this —
// the binding certificate partitions the cache, so it must be resolved, and the callback invoked,
// before the cache can be read (see TestSignedAssertionCallbackCertificateKeysTheCache). Supplying
// the certificate explicitly to skip that is no longer possible; it is rejected outright, see
// TestSignedAssertionExplicitCertificateRejected.
func TestSignedAssertionCallbackNotInvokedOnCacheHit(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "cached-binding-cert")
	var calls int32

	tenant := "tenant"
	lmo := "login.microsoftonline.com"
	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenant)))
	cred := NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
		atomic.AddInt32(&calls, 1)
		return SignedAssertion{Assertion: "assertion", BindingCertificate: tlsCertFor(leaf, key)}, nil
	})
	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred, WithHTTPClient(mockClient))
	if err != nil {
		t.Fatal(err)
	}
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody("cached-token", "", "", "", 3600, 0)))
	ctx := context.Background()

	first, err := client.AcquireTokenByCredential(ctx, tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if first.Metadata.TokenSource != TokenSourceIdentityProvider {
		t.Fatalf("first call TokenSource = %d, want the identity provider", first.Metadata.TokenSource)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("callback invoked %d times for the first acquisition, want 1", got)
	}

	// The mock has no responses queued, so a second token request would fail: the hit below is a
	// real cache hit rather than a silently repeated network call.
	cached, err := client.AcquireTokenByCredential(ctx, tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if cached.Metadata.TokenSource != TokenSourceCache {
		t.Fatalf("second call TokenSource = %d, want cache", cached.Metadata.TokenSource)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("callback invoked %d times across two acquisitions, want 1: a cache hit must not re-run leg 1", got)
	}
	if cached.AccessToken != first.AccessToken {
		t.Error("the cached token is not the one the first acquisition returned")
	}
}

// TestSignedAssertionCallbackCertificatePartitionsCache proves the callback's certificate reaches
// the cache key and not just the handshake: a second acquisition whose callback returns a different
// certificate must miss the cache and go to the wire, because a token bound to certificate A is
// unusable when presenting certificate B.
func TestSignedAssertionCallbackCertificatePartitionsCache(t *testing.T) {
	first, firstKey := newSelfSignedCert(t, "rotation-cert-a")
	second, secondKey := newSelfSignedCert(t, "rotation-cert-b")
	var rotated int32

	srvA := newMtlsHandshakeServer(t, mtlsPoPTokenBody("token-a", 3600))
	srvB := newMtlsHandshakeServer(t, mtlsPoPTokenBody("token-b", 3600))

	cred := NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
		if atomic.LoadInt32(&rotated) == 0 {
			return SignedAssertion{Assertion: "assertion-a", BindingCertificate: tlsCertFor(first, firstKey)}, nil
		}
		return SignedAssertion{Assertion: "assertion-b", BindingCertificate: tlsCertFor(second, secondKey)}, nil
	})

	tenant := "tenant"
	lmo := "login.microsoftonline.com"
	// Route each acquisition to its own server so the assertions below can't be confused by
	// connection reuse.
	factoryA, factoryB := srvA.clientFactory(), srvB.clientFactory()
	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(discoveryClient{host: lmo, tenant: tenant}),
		WithMtlsHTTPClient(func(cert tls.Certificate) *http.Client {
			if cert.Leaf != nil && cert.Leaf.Equal(second) {
				return factoryB(cert)
			}
			return factoryA(cert)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	resA, err := client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}
	if resA.AccessToken != "token-a" {
		t.Fatalf("first AccessToken = %q, want token-a", resA.AccessToken)
	}

	atomic.StoreInt32(&rotated, 1)
	resB, err := client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}
	if resB.Metadata.TokenSource != TokenSourceIdentityProvider {
		t.Error("a rotated binding certificate must miss the cache; the cache key ignores the callback's certificate")
	}
	if resB.AccessToken != "token-b" {
		t.Errorf("second AccessToken = %q, want token-b", resB.AccessToken)
	}
	if got := srvA.presented(t); !got.Equal(first) {
		t.Error("the first acquisition did not present the first certificate")
	}
	if got := srvB.presented(t); !got.Equal(second) {
		t.Error("the second acquisition did not present the rotated certificate")
	}
}

// TestSignedAssertionExplicitCertificateRejected replaces the precedence rule this test used to pin.
//
// The old rule — an explicitly supplied binding certificate wins over the callback's — was unsafe.
// The callback stayed lazy under it, so it could return an assertion bound to certificate A while
// the handshake presented explicit certificate B, and its certificate was silently discarded: the
// exact assertion/certificate mismatch NewCredFromSignedAssertionCallback exists to prevent. MSAL
// .NET has no explicit-binding-certificate option to defer to (the certificate comes only from
// ClientSignedAssertion.TokenBindingCertificate, and a signed-assertion credential that returns none
// throws MtlsCertificateNotProvided), so there was no precedence to match. The combination is now
// rejected, which keeps the pairing atomic.
func TestSignedAssertionExplicitCertificateRejected(t *testing.T) {
	callbackCert, callbackKey := newSelfSignedCert(t, "callback-cert")
	explicitCert, explicitKey := newSelfSignedCert(t, "explicit-cert")

	for _, test := range []struct {
		name string
		opt  MtlsPoPOption
	}{
		{"WithMtlsBindingTLSCertificate", WithMtlsBindingTLSCertificate(tlsCertFor(explicitCert, explicitKey))},
		{"WithMtlsBindingCertificate", WithMtlsBindingCertificate([]*x509.Certificate{explicitCert}, explicitKey)},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls int32
			srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("final-mtls-token", 3600))
			cred := NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
				atomic.AddInt32(&calls, 1)
				return SignedAssertion{
					Assertion:          "callback-assertion",
					BindingCertificate: tlsCertFor(callbackCert, callbackKey),
				}, nil
			})
			client := handshakeTestClient(t, cred, srv)

			_, err := client.AcquireTokenByCredential(context.Background(), tokenScope,
				WithMtlsProofOfPossession(test.opt))
			if err == nil {
				t.Fatal("an explicit binding certificate combined with a signed-assertion credential must be rejected")
			}
			if !errors.Is(err, errMtlsPoPSignedAssertionWithExplicitCert) {
				t.Fatalf("error = %v, want errMtlsPoPSignedAssertionWithExplicitCert", err)
			}
			// The error has to name both halves of the combination, or the caller can't tell which
			// of the two APIs to drop.
			for _, want := range []string{test.name, "NewCredFromSignedAssertionCallback"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %s", err, want)
				}
			}
			if got := atomic.LoadInt32(&calls); got != 0 {
				t.Errorf("signed-assertion callback invoked %d times, want 0: the combination must be rejected before leg 1 runs", got)
			}
			if got := srv.tokenCalls(); got != 0 {
				t.Errorf("token endpoint called %d times, want 0", got)
			}
		})
	}
}

// TestExplicitCertificateStillAllowedWithAssertionCallback is the control for the rejection above: it
// applies only to NewCredFromSignedAssertionCallback. A plain assertion credential has no certificate
// of its own, so an explicit one is the only way it can do mTLS proof-of-possession at all — the
// legacy FIC leg-2 path — and must keep working.
func TestExplicitCertificateStillAllowedWithAssertionCallback(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "legacy-leg2-cert")
	srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("final-mtls-token", 3600))
	cred := NewCredFromAssertionCallback(func(context.Context, AssertionRequestOptions) (string, error) {
		return "leg1-assertion", nil
	})
	client := handshakeTestClient(t, cred, srv)

	if _, err := client.AcquireTokenByCredential(context.Background(), tokenScope,
		WithMtlsProofOfPossession(WithMtlsBindingTLSCertificate(tlsCertFor(leaf, key)))); err != nil {
		t.Fatalf("a plain assertion credential with an explicit binding certificate must still work: %v", err)
	}
	if got := srv.presented(t); !got.Equal(leaf) {
		t.Errorf("handshake presented %q, want the explicitly supplied certificate", got.Subject.CommonName)
	}
}

// TestSignedAssertionEmptyAssertionRejected covers a callback that returns no assertion. MSAL must
// reject it locally instead of memoizing it and sending an empty client_assertion, which the
// identity provider rejects as a malformed token request — an error that says nothing about which
// callback misbehaved. MSAL .NET validates the same credential result locally and returns
// InvalidClientAssertion.
func TestSignedAssertionEmptyAssertionRejected(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "empty-assertion-binding-cert")
	for _, test := range []struct {
		name, assertion string
	}{
		{"empty", ""},
		{"whitespace only", " \t\r\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("final-mtls-token", 3600))
			cred := NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
				return SignedAssertion{Assertion: test.assertion, BindingCertificate: tlsCertFor(leaf, key)}, nil
			})
			client := handshakeTestClient(t, cred, srv)

			_, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
			if err == nil {
				t.Fatal("an empty client assertion must be rejected before the request is sent")
			}
			if !strings.Contains(err.Error(), "empty client assertion") {
				t.Errorf("error %q does not identify the empty assertion", err)
			}
			if got := srv.tokenCalls(); got != 0 {
				t.Errorf("token endpoint called %d times, want 0: an empty assertion must not reach the network", got)
			}
		})
	}
}

// TestSignedAssertionNilBindingCertificateErrors covers a SignedAssertion that carries no
// certificate on a client that has none of its own: it must degrade to an actionable error rather
// than crash. Supplying the missing certificate through WithMtlsBindingCertificate is not the
// remedy — that combination is rejected, see TestSignedAssertionExplicitCertificateRejected — so the
// callback has to return one.
func TestSignedAssertionNilBindingCertificateErrors(t *testing.T) {
	srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("final-mtls-token", 3600))
	cred := NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
		return SignedAssertion{Assertion: "assertion"}, nil
	})
	client := handshakeTestClient(t, cred, srv)
	// The client's credential has no certificate, so the nil binding certificate must surface as
	// the ordinary "no certificate available" error, not a panic.
	_, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("expected an error when neither the callback nor the client supplies a certificate")
	}
	if !strings.Contains(err.Error(), "mTLS proof-of-possession requires") {
		t.Errorf("error %q does not explain how to supply a binding certificate", err)
	}
	if got := srv.tokenCalls(); got != 0 {
		t.Errorf("token endpoint called %d times, want 0", got)
	}
}

// TestSignedAssertionOpaqueSignerHandshake is the KeyGuard case: the binding certificate's key is a
// non-exportable crypto.Signer, so any hidden *rsa.PrivateKey type assertion between the callback and
// the TLS handshake breaks it. opaqueRSASigner refuses to expose its inner key, and the handshake
// only completes if crypto/tls signs through the Signer interface.
func TestSignedAssertionOpaqueSignerHandshake(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "keyguard-binding-cert")
	signer := &opaqueRSASigner{inner: key}
	srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("final-mtls-token", 3600))

	cred := NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
		return SignedAssertion{
			Assertion:          "keyguard-assertion",
			BindingCertificate: tlsCertFor(leaf, signer),
		}, nil
	})
	client := handshakeTestClient(t, cred, srv)

	res, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}
	if got := srv.presented(t); !got.Equal(leaf) {
		t.Error("the opaque signer's certificate was not presented on the handshake")
	}
	if atomic.LoadInt32(&signer.signs) == 0 {
		t.Error("the opaque signer was never asked to sign, so the handshake did not use it")
	}
	if res.BindingCertificate == nil {
		t.Fatal("AuthResult.BindingCertificate is nil")
	}
	if _, ok := res.BindingCertificate.PrivateKey.(*rsa.PrivateKey); ok {
		t.Fatal("the returned key is an *rsa.PrivateKey; the test signer leaked and proves nothing")
	}
	if res.BindingCertificate.PrivateKey != crypto.PrivateKey(signer) {
		t.Error("AuthResult.BindingCertificate.PrivateKey is not the opaque signer the callback supplied")
	}
}

// TestSignedAssertionCredentialWithoutMtls pins the compatibility requirement: used without mTLS
// proof-of-possession, a signed-assertion credential behaves exactly like one from
// NewCredFromAssertionCallback — a bearer client_assertion, the callback invoked lazily and only
// once, its certificate ignored, and the same AssertionRequestOptions delivered.
func TestSignedAssertionCredentialWithoutMtls(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "ignored-binding-cert")
	var calls int32
	var gotOpts AssertionRequestOptions

	tenant := "tenant"
	lmo := "login.microsoftonline.com"
	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenant)))
	cred := NewCredFromSignedAssertionCallback(func(_ context.Context, opts AssertionRequestOptions) (SignedAssertion, error) {
		atomic.AddInt32(&calls, 1)
		gotOpts = opts
		return SignedAssertion{Assertion: "bearer-assertion", BindingCertificate: tlsCertFor(leaf, key)}, nil
	})
	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred, WithHTTPClient(mockClient))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	var body url.Values
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody("bearer-token", "", "", "", 3600, 0)),
		mock.WithCallback(func(r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			body, _ = url.ParseQuery(string(raw))
		}),
	)

	res, err := client.AcquireTokenByCredential(ctx, tokenScope, WithFMIPath("fmi/path"))
	if err != nil {
		t.Fatal(err)
	}
	if res.AccessToken != "bearer-token" {
		t.Errorf("AccessToken = %q, want bearer-token", res.AccessToken)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("callback invoked %d times, want exactly 1", got)
	}
	if got := body.Get("client_assertion"); got != "bearer-assertion" {
		t.Errorf("client_assertion = %q, want bearer-assertion", got)
	}
	if got := body.Get("client_assertion_type"); got != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("client_assertion_type = %q, want the jwt-bearer value: a non-mTLS request must not be marked certificate-bound", got)
	}
	if res.BindingCertificate != nil {
		t.Error("a bearer token must not report a binding certificate")
	}
	if gotOpts.ClientID != fakeClientID {
		t.Errorf("callback ClientID = %q, want %q", gotOpts.ClientID, fakeClientID)
	}
	if gotOpts.FMIPath != "fmi/path" {
		t.Errorf("callback FMIPath = %q, want fmi/path", gotOpts.FMIPath)
	}
	if !strings.Contains(gotOpts.TokenEndpoint, lmo) {
		t.Errorf("callback TokenEndpoint = %q, want the resolved %s endpoint", gotOpts.TokenEndpoint, lmo)
	}
}

// TestSignedAssertionCallbackReceivesResolvedTokenEndpoint guards the ordering fix from regressing
// into a silent behavior change: pulling the callback forward must not hand it an empty token
// endpoint, which applications use as their assertion's "aud" claim.
func TestSignedAssertionCallbackReceivesResolvedTokenEndpoint(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "endpoint-binding-cert")
	var gotOpts AssertionRequestOptions
	srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("final-mtls-token", 3600))

	cred := NewCredFromSignedAssertionCallback(func(_ context.Context, opts AssertionRequestOptions) (SignedAssertion, error) {
		gotOpts = opts
		return SignedAssertion{Assertion: "assertion", BindingCertificate: tlsCertFor(leaf, key)}, nil
	})
	client := handshakeTestClient(t, cred, srv)

	if _, err := client.AcquireTokenByCredential(context.Background(), tokenScope,
		WithMtlsProofOfPossession(), WithFMIPath("fmi/path")); err != nil {
		t.Fatal(err)
	}
	if gotOpts.ClientID != fakeClientID {
		t.Errorf("callback ClientID = %q, want %q", gotOpts.ClientID, fakeClientID)
	}
	if gotOpts.FMIPath != "fmi/path" {
		t.Errorf("callback FMIPath = %q, want fmi/path", gotOpts.FMIPath)
	}
	if !strings.HasPrefix(gotOpts.TokenEndpoint, "https://login.microsoftonline.com/") {
		t.Errorf("callback TokenEndpoint = %q, want the resolved login.microsoftonline.com endpoint", gotOpts.TokenEndpoint)
	}
}

// TestSignedAssertionCallbackErrorPropagates keeps a failing leg 1 from being swallowed: the caller
// must see their own error, not a generic "no binding certificate" message.
func TestSignedAssertionCallbackErrorPropagates(t *testing.T) {
	sentinel := errors.New("leg 1 failed")
	srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("unused", 3600))
	cred := NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
		return SignedAssertion{}, sentinel
	})
	client := handshakeTestClient(t, cred, srv)

	_, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want the callback's error", err)
	}
}

// TestSignedAssertionCallbackUnusableCertificate covers a callback that returns a certificate MSAL
// can't present: the caller gets a clear error naming the callback, before any token request.
func TestSignedAssertionCallbackUnusableCertificate(t *testing.T) {
	leaf, _ := newSelfSignedCert(t, "keyless-binding-cert")
	srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("unused", 3600))
	cred := NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
		return SignedAssertion{
			Assertion:          "assertion",
			BindingCertificate: &tls.Certificate{Certificate: [][]byte{leaf.Raw}, Leaf: leaf},
		}, nil
	})
	client := handshakeTestClient(t, cred, srv)

	_, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("expected an error for a binding certificate with no private key")
	}
	if !strings.Contains(err.Error(), "signed-assertion callback") || !strings.Contains(err.Error(), "no private key") {
		t.Errorf("error %q does not identify the callback's certificate as the problem", err)
	}
}

// TestSignedAssertionCallbackCopiesCertificate proves MSAL copies the callback's certificate too:
// an application that hands back a struct it keeps mutating (a rotation buffer) must not have that
// mutation reach an in-flight acquisition.
func TestSignedAssertionCallbackCopiesCertificate(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "callback-original-cert")
	other, _ := newSelfSignedCert(t, "callback-swapped-cert")
	shared := tlsCertFor(leaf, key)

	srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("final-mtls-token", 3600))
	cred := NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
		return SignedAssertion{Assertion: "assertion", BindingCertificate: shared}, nil
	})
	client := handshakeTestClient(t, cred, srv)

	done := make(chan error, 1)
	go func() {
		_, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
		done <- err
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// After the acquisition the application rotates its struct in place. The result MSAL already
	// handed back must not change with it.
	shared.Certificate[0] = other.Raw
	shared.Leaf = other

	if got := srv.presented(t); !got.Equal(leaf) {
		t.Errorf("handshake presented %q, want %q", got.Subject.CommonName, leaf.Subject.CommonName)
	}
}

// TestSignedAssertionCallbackCertificateKeysTheCache proves the eagerly resolved certificate really
// is what the cache is keyed on. The app token cache is partitioned by the mTLS PoP authentication
// scheme's KeyID (the certificate thumbprint), and AcquireTokenByCredential reads it before falling
// through to the token endpoint. If the callback's certificate did not reach that key, the second
// acquisition would miss and issue a second token request.
func TestSignedAssertionCallbackCertificateKeysTheCache(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "cache-key-binding-cert")
	var calls int32
	srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("final-mtls-token", 3600))

	cred := NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
		atomic.AddInt32(&calls, 1)
		return SignedAssertion{Assertion: "assertion", BindingCertificate: tlsCertFor(leaf, key)}, nil
	})
	client := handshakeTestClient(t, cred, srv)
	ctx := context.Background()

	acquired, err := client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}

	cached, err := client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}
	if cached.Metadata.TokenSource != TokenSourceCache {
		t.Errorf("second acquisition TokenSource = %d, want the cache", cached.Metadata.TokenSource)
	}
	if cached.AccessToken != acquired.AccessToken {
		t.Error("the cache lookup did not find the token stored under the callback's certificate")
	}
	if cached.BindingCertificate == nil || cached.BindingCertificate.Leaf == nil || !cached.BindingCertificate.Leaf.Equal(leaf) {
		t.Error("the cached result does not carry the callback's binding certificate")
	}
	if got := srv.tokenCalls(); got != 1 {
		t.Errorf("token endpoint called %d times, want 1 (the second acquisition must be served from the cache)", got)
	}
	// One invocation per request, never more: the certificate is needed before the cache read, so
	// the callback can't be skipped on a hit, but it must not fire twice for a single request.
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("callback invoked %d times across two acquisitions, want exactly 2 (once each)", got)
	}
}

// TestNewCredFromSignedAssertionCallbackNil mirrors TestInvalidCredential: a nil callback is not a
// usable credential and must be rejected at construction time, not dereferenced later.
func TestNewCredFromSignedAssertionCallbackNil(t *testing.T) {
	if _, err := New(fakeAuthority, fakeClientID, NewCredFromSignedAssertionCallback(nil)); err == nil {
		t.Fatal("expected an error for a nil signed-assertion callback")
	}
}

// opaqueRSASigner is a crypto.Signer whose inner key is unreachable through any type assertion,
// modelling a non-exportable platform key (Windows KeyGuard, CNG, an HSM). It counts signatures so
// tests can prove the TLS handshake actually went through the Signer interface.
type opaqueRSASigner struct {
	inner *rsa.PrivateKey
	signs int32
}

func (s *opaqueRSASigner) Public() crypto.PublicKey { return s.inner.Public() }

func (s *opaqueRSASigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	atomic.AddInt32(&s.signs, 1)
	return s.inner.Sign(r, digest, opts)
}
