// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

// bearerMtlsCallbackCred builds a signed-assertion credential whose callback returns the test
// certificate as its binding certificate, and reports how many times the callback ran.
//
// The counter is what proves the callback is pulled forward rather than invoked twice: MSAL .NET
// documents calling its delegate twice on a network request (once to read TokenBindingCertificate,
// once to build the body), and Go deliberately does not.
func bearerMtlsCallbackCred(t *testing.T, withCert bool) (Credential, *int32) {
	t.Helper()
	certs, key := loadTestCert(t)
	var calls int32
	cred := NewCredFromSignedAssertionCallback(
		func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
			atomic.AddInt32(&calls, 1)
			s := SignedAssertion{Assertion: "signed-assertion"}
			if withCert {
				s.BindingCertificate = &tls.Certificate{
					Certificate: [][]byte{certs[0].Raw},
					PrivateKey:  key,
					Leaf:        certs[0],
				}
			}
			return s, nil
		})
	return cred, &calls
}

// TestSendCertificateOverMtls_SignedAssertion_UsesCallbackCertificate is the core of Gladwin's
// finding: a signed-assertion callback returns its assertion and a binding certificate as one
// atomic result, and the Bearer-over-mTLS path must use that certificate for the transport even
// though the token it asks for stays a plain bearer token.
//
// Before this, the certificate was discarded unless WithMtlsProofOfPossession was also passed, and
// New refused the combination outright. MSAL .NET uses it here too, in
// MtlsPopParametersInitializer.TryInitImplicitBearerOverMtlsAsync.
//
// The assertion is checked as well as the endpoint: the callback's assertion must be the one that
// reaches the wire. Asserting only on the mtlsauth host would pass even if the certificate were
// used while the assertion came from somewhere else, which is exactly the "sourced independently"
// failure the atomic result exists to prevent.
func TestSendCertificateOverMtls_SignedAssertion_UsesCallbackCertificate(t *testing.T) {
	cred, calls := bearerMtlsCallbackCred(t, true)
	client, router := newBearerMtlsClient(t, cred, bearerMtlsControlAuthority)

	res, err := client.AcquireTokenByCredential(context.Background(), tokenScope)
	if err != nil {
		t.Fatal(err)
	}

	got := router.tokenRequest()
	if got == nil {
		t.Fatal("no token request was sent")
	}
	if !strings.HasPrefix(got.Host, "mtlsauth.") {
		t.Errorf("token request went to %q, want the mtlsauth.* endpoint; the callback's certificate was not used for the transport", got.Host)
	}

	// The token stays Bearer. This is what separates Bearer-over-mTLS from mTLS PoP: only the
	// transport and the endpoint change, so a caller must not receive a certificate-bound token it
	// never asked for.
	if res.BindingCertificate != nil {
		t.Error("AuthResult.BindingCertificate is set; a Bearer-over-mTLS result must not advertise a bound token")
	}

	if n := atomic.LoadInt32(calls); n != 1 {
		t.Errorf("the signed-assertion callback ran %d times, want exactly 1; it is pulled forward, not invoked once for the certificate and again for the request body", n)
	}
}

// TestSendCertificateOverMtls_SignedAssertion_CallbackAssertionReachesTheWire pins the other half of
// the atomic result: the assertion the callback returned alongside the certificate is the one sent.
//
// Without this, the test above would still pass if MSAL used the callback's certificate but built
// the request body from a second, independent call - the divergence the single-callback design
// exists to make impossible.
func TestSendCertificateOverMtls_SignedAssertion_CallbackAssertionReachesTheWire(t *testing.T) {
	certs, key := loadTestCert(t)
	const wantAssertion = "the-one-and-only-assertion"
	var calls int32
	cred := NewCredFromSignedAssertionCallback(
		func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
			n := atomic.AddInt32(&calls, 1)
			// A second invocation returns a different assertion, so if the request body were built
			// from a second call the wire value would not match wantAssertion.
			assertion := wantAssertion
			if n > 1 {
				assertion = "a-second-different-assertion"
			}
			return SignedAssertion{
				Assertion: assertion,
				BindingCertificate: &tls.Certificate{
					Certificate: [][]byte{certs[0].Raw},
					PrivateKey:  key,
					Leaf:        certs[0],
				},
			}, nil
		})

	client, router := newBearerMtlsClient(t, cred, bearerMtlsControlAuthority)
	if _, err := client.AcquireTokenByCredential(context.Background(), tokenScope); err != nil {
		t.Fatal(err)
	}
	if router.tokenRequest() == nil {
		t.Fatal("no token request was sent")
	}
	body := router.tokenRequestBody()
	if body == nil {
		t.Fatal("the token request body was not recorded")
	}
	if got := body.Get("client_assertion"); got != wantAssertion {
		t.Errorf("client_assertion = %q, want %q; the assertion on the wire is not the one returned with the certificate", got, wantAssertion)
	}
}

// TestSendCertificateOverMtls_SignedAssertion_NoCertificateFailsClosed pins that a callback which
// returns no certificate fails the request rather than silently falling back to the plain token
// endpoint.
//
// The application asked for mutual TLS with WithSendCertificateOverMtls. Quietly sending its client
// assertion to login.* instead would be a downgrade it never agreed to, and would look identical to
// success. This is the same fail-closed stance MSAL .NET took in #6081 for attestation.
func TestSendCertificateOverMtls_SignedAssertion_NoCertificateFailsClosed(t *testing.T) {
	cred, _ := bearerMtlsCallbackCred(t, false)
	client, router := newBearerMtlsClient(t, cred, bearerMtlsControlAuthority)

	_, err := client.AcquireTokenByCredential(context.Background(), tokenScope)
	if err == nil {
		t.Fatal("AcquireTokenByCredential = nil error, want a callback that returns no binding certificate to fail")
	}
	if !strings.Contains(err.Error(), "BindingCertificate") {
		t.Errorf("error = %q, want it to name SignedAssertion.BindingCertificate, the only thing that can fix it", err)
	}
	if got := router.tokenRequest(); got != nil {
		t.Errorf("a token request was sent to %s; the request must fail rather than downgrade to the plain endpoint", got)
	}
}

// TestSendCertificateOverMtls_SignedAssertion_UnusableCertificateRejected pins that the callback's
// certificate goes through the same validation a certificate credential's does, so a certificate
// whose key does not match its leaf cannot reach the handshake.
//
// The error text is asserted, not just the failure: an unusable certificate is also caught further
// down the stack, so asserting only "some error occurred" would pass even if this path stopped
// validating at all. Matching the wrapper prepareBearerOverMtls adds is what makes the assertion
// attributable to this path, and keeps the caller pointed at their callback rather than at an
// opaque transport failure.
func TestSendCertificateOverMtls_SignedAssertion_UnusableCertificateRejected(t *testing.T) {
	certs, _ := loadTestCert(t)
	cred := NewCredFromSignedAssertionCallback(
		func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
			// A certificate with no private key at all: nothing can sign the handshake with it.
			return SignedAssertion{
				Assertion:          "assertion",
				BindingCertificate: &tls.Certificate{Certificate: [][]byte{certs[0].Raw}, Leaf: certs[0]},
			}, nil
		})
	client, router := newBearerMtlsClient(t, cred, bearerMtlsControlAuthority)

	_, err := client.AcquireTokenByCredential(context.Background(), tokenScope)
	if err == nil {
		t.Fatal("AcquireTokenByCredential = nil error, want an unusable binding certificate to be rejected")
	}
	if !strings.Contains(err.Error(), "signed-assertion callback returned an unusable binding certificate") {
		t.Errorf("error = %q, want it to name the callback as the source; the rejection is not coming from prepareBearerOverMtls", err)
	}
	if !strings.Contains(err.Error(), "no private key") {
		t.Errorf("error = %q, want it to carry the underlying reason from validBindingCertificate", err)
	}
	if got := router.tokenRequest(); got != nil {
		t.Errorf("a token request was sent to %s; an unusable certificate must be rejected first", got)
	}
}

// TestSendCertificateOverMtls_SignedAssertion_CertificateCredentialUnaffected is the control for
// this file. The signed-assertion branch is new; without this, a regression that broke the ordinary
// certificate-credential path would still leave every test above green.
func TestSendCertificateOverMtls_SignedAssertion_CertificateCredentialUnaffected(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	client, router := newBearerMtlsClient(t, cred, bearerMtlsControlAuthority)

	if _, err := client.AcquireTokenByCredential(context.Background(), tokenScope); err != nil {
		t.Fatal(err)
	}
	got := router.tokenRequest()
	if got == nil {
		t.Fatal("no token request was sent")
	}
	if !strings.HasPrefix(got.Host, "mtlsauth.") {
		t.Errorf("token request went to %q, want the mtlsauth.* endpoint", got.Host)
	}
}

// TestSendCertificateOverMtls_SignedAssertion_RealHandshake is the loopback-TLS proof for this
// flow: an actual TLS 1.2+ handshake against a server that requires a client certificate, so the
// certificate assertion comes from the TLS layer rather than from a mock that was handed the value
// it is asked to confirm.
//
// It pins all three properties together, which is the combination that matters: the callback runs
// once, the certificate it returned is the one presented on the wire, and the access token that
// comes back is still Bearer. Any two of those without the third would describe a different flow —
// mTLS PoP, or a plain bearer request that never reached mutual TLS.
func TestSendCertificateOverMtls_SignedAssertion_RealHandshake(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "bearer-over-mtls-binding-cert")
	var calls int32
	srv := newMtlsHandshakeServer(t, mock.GetAccessTokenBody("bearer-over-mtls-token", "", "", "", 3600, 0))

	cred := NewCredFromSignedAssertionCallback(
		func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
			atomic.AddInt32(&calls, 1)
			return SignedAssertion{Assertion: "handshake-assertion", BindingCertificate: tlsCertFor(leaf, key)}, nil
		})

	tenant, lmo := "tenant", "login.microsoftonline.com"
	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(discoveryClient{host: lmo, tenant: tenant}),
		WithMtlsHTTPClient(srv.clientFactory()),
		WithSendCertificateOverMtls(),
	)
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.AcquireTokenByCredential(context.Background(), tokenScope)
	if err != nil {
		t.Fatal(err)
	}

	// presented also asserts the endpoint was called exactly once.
	if got := srv.presented(t); !got.Equal(leaf) {
		t.Error("the certificate presented on the handshake is not the one the callback returned")
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("the signed-assertion callback ran %d times, want exactly 1", n)
	}
	if got := srv.form(t).Get("client_assertion"); got != "handshake-assertion" {
		t.Errorf("client_assertion = %q, want the assertion returned with the certificate", got)
	}
	// The request went to the mutual-TLS endpoint, not the plain one. srv answers whatever host it
	// is dialed with, so this is read from the Host header MSAL sent.
	if got := srv.host(t); !strings.HasPrefix(got, "mtlsauth.") {
		t.Errorf("token request Host = %q, want the mtlsauth.* endpoint", got)
	}
	// Bearer, not PoP: only the transport changed.
	if res.BindingCertificate != nil {
		t.Error("AuthResult.BindingCertificate is set; a Bearer-over-mTLS result must not advertise a bound token")
	}
	if res.AccessToken != "bearer-over-mtls-token" {
		t.Errorf("AccessToken = %q, want the token the endpoint returned", res.AccessToken)
	}
}

// TestSendCertificateOverMtls_SignedAssertion_NotPulledForwardWithoutTheOption pins that the
// callback stays lazy when the application did not ask for mutual TLS.
//
// This is the cost MSAL .NET pays and Go does not: .NET's implicit case resolves the delegate on
// every request, cache hits included, because returning a certificate is itself the opt-in there.
// Go gates on WithSendCertificateOverMtls, so a plain client keeps the ordinary lazy behavior and
// this assertion is what stops that from being quietly lost.
func TestSendCertificateOverMtls_SignedAssertion_NotPulledForwardWithoutTheOption(t *testing.T) {
	cred, calls := bearerMtlsCallbackCred(t, true)
	client, err := New(bearerMtlsControlAuthority, fakeClientID, cred,
		WithHTTPClient(&countingClient{}))
	if err != nil {
		t.Fatal(err)
	}
	// The request itself fails: countingClient refuses every request. What matters is only whether
	// the callback ran before the network was reached.
	_, _ = client.AcquireTokenByCredential(context.Background(), tokenScope)
	if n := atomic.LoadInt32(calls); n != 0 {
		t.Errorf("the signed-assertion callback ran %d times before the network was touched, want 0; without WithSendCertificateOverMtls nothing needs a certificate ahead of the request body", n)
	}
}
