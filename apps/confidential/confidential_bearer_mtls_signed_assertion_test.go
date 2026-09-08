// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

func TestSendCertificateOverMtlsSignedCallbackUsesFinalEndpointAndOptions(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "callback-options")
	const claims = `{"access_token":{"essential":true}}`
	for _, test := range []struct {
		name      string
		authority string
		region    string
		private   bool
		want      string
	}{
		{
			name:      "global",
			authority: "https://login.microsoftonline.com/tenant",
			want:      "https://mtlsauth.microsoft.com/tenant/oauth2/v2.0/token",
		},
		{
			name:      "regional",
			authority: "https://login.microsoftonline.com/tenant",
			region:    "westus3",
			want:      "https://westus3.mtlsauth.microsoft.com/tenant/oauth2/v2.0/token",
		},
		{
			name:      "US Government",
			authority: "https://login.microsoftonline.us/tenant",
			want:      "https://mtlsauth.microsoftonline.us/tenant/oauth2/v2.0/token",
		},
		{
			name:      "China",
			authority: "https://login.partner.microsoftonline.cn/tenant",
			want:      "https://mtlsauth.partner.microsoftonline.cn/tenant/oauth2/v2.0/token",
		},
		{
			name:      "private cloud",
			authority: "https://login.private.example/tenant",
			private:   true,
			want:      "https://mtlsauth.private.example/tenant/oauth2/v2.0/token",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var got AssertionRequestOptions
			cred := NewCredFromSignedAssertionCallback(func(_ context.Context, opts AssertionRequestOptions) (SignedAssertion, error) {
				got = opts
				return SignedAssertion{Assertion: "opaque-assertion", BindingCertificate: tlsCertFor(leaf, key)}, nil
			})
			var opts []Option
			if test.region != "" {
				opts = append(opts, WithAzureRegion(test.region))
			}

			t.Run("public flow jwt-pop", func(t *testing.T) {
				for _, test := range []struct {
					name    string
					acquire func(Client) (AuthResult, error)
				}{
					{
						name: "client credential",
						acquire: func(client Client) (AuthResult, error) {
							return client.AcquireTokenByCredential(context.Background(), tokenScope)
						},
					},
					{
						name: "authorization code",
						acquire: func(client Client) (AuthResult, error) {
							return client.AcquireTokenByAuthCode(context.Background(), "code", "https://localhost", tokenScope)
						},
					},
					{
						name: "on behalf of",
						acquire: func(client Client) (AuthResult, error) {
							return client.AcquireTokenOnBehalfOf(context.Background(), "user-assertion", tokenScope)
						},
					},
				} {
					t.Run(test.name, func(t *testing.T) {
						leaf, key := newSelfSignedCert(t, test.name)
						var gotOpts AssertionRequestOptions
						cred := NewCredFromSignedAssertionCallback(func(_ context.Context, opts AssertionRequestOptions) (SignedAssertion, error) {
							gotOpts = opts
							return SignedAssertion{Assertion: "bound-assertion", BindingCertificate: tlsCertFor(leaf, key)}, nil
						})
						client, router := newBearerMtlsClient(t, cred, bearerMtlsControlAuthority)
						if _, err := test.acquire(client); err != nil {
							t.Fatal(err)
						}
						req := router.tokenRequest()
						form := router.tokenRequestBody()
						if req == nil || form == nil {
							t.Fatal("no token request was recorded")
						}
						if gotOpts.TokenEndpoint != req.String() {
							t.Errorf("callback endpoint = %q, request URI = %q", gotOpts.TokenEndpoint, req)
						}
						if requestID := router.tokenRequestHeader().Get("client-request-id"); requestID != gotOpts.CorrelationID {
							t.Errorf("request client-request-id = %q, callback CorrelationID = %q", requestID, gotOpts.CorrelationID)
						}
						if got := form.Get("client_assertion"); got != "bound-assertion" {
							t.Errorf("client_assertion = %q, want callback result", got)
						}
						if got := form.Get("client_assertion_type"); !strings.HasSuffix(got, "jwt-pop") {
							t.Errorf("client_assertion_type = %q, want jwt-pop", got)
						}
					})
				}
			})

			t.Run("silent refresh jwt-pop", func(t *testing.T) {
				leaf, key := newSelfSignedCert(t, "silent-refresh")
				var callbackOptions []AssertionRequestOptions
				cred := NewCredFromSignedAssertionCallback(func(_ context.Context, opts AssertionRequestOptions) (SignedAssertion, error) {
					callbackOptions = append(callbackOptions, opts)
					return SignedAssertion{Assertion: "bound-assertion", BindingCertificate: tlsCertFor(leaf, key)}, nil
				})

				const (
					tenant = "tenant"
					lmo    = "login.microsoftonline.com"
				)
				clientInfo := base64.RawStdEncoding.EncodeToString([]byte(`{"uid":"uid","utid":"utid"}`))
				idToken := mock.GetIDToken(tenant, fmt.Sprintf(authorityFmt, lmo, tenant))
				mockClient := mock.NewClient()
				mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
				mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody("seed", idToken, "refresh-token", clientInfo, 1, 0)))

				client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
					WithHTTPClient(mockClient),
					WithMtlsHTTPClient(mockMtlsFactory(mockClient)),
					WithInstanceDiscovery(false),
					WithSendCertificateOverMtls(),
				)
				if err != nil {
					t.Fatal(err)
				}

				t.Run("certificate ownership boundaries", func(t *testing.T) {
					leaf, key := newSelfSignedCert(t, "ownership")
					caller := &tls.Certificate{
						Certificate:                  [][]byte{append([]byte(nil), leaf.Raw...)},
						PrivateKey:                   key,
						Leaf:                         leaf,
						SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.PKCS1WithSHA256},
						OCSPStaple:                   []byte{1, 2, 3},
						SignedCertificateTimestamps:  [][]byte{{4, 5, 6}},
					}
					cred := NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
						return SignedAssertion{Assertion: "bound-assertion", BindingCertificate: caller}, nil
					})
					router := &bearerMtlsRouter{
						host:      "login.microsoftonline.com",
						tenant:    "tenant",
						tokenBody: mtlsPoPTokenBody("mtls-pop-token", 3600),
					}
					var factoryCert tls.Certificate
					client, err := New("https://login.microsoftonline.com/tenant", fakeClientID, cred,
						WithHTTPClient(router),
						WithMtlsHTTPClient(func(cert tls.Certificate) *http.Client {
							factoryCert = cert
							return &http.Client{Transport: bearerMtlsRoundTripper{router: router}}
						}),
					)
					if err != nil {
						t.Fatal(err)
					}
					result, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
					if err != nil {
						t.Fatal(err)
					}
					if result.BindingCertificate == nil {
						t.Fatal("result has no binding certificate")
					}

					mutate := func(cert *tls.Certificate, marker byte, algorithm tls.SignatureScheme) {
						cert.Certificate[0][0] = marker
						cert.Leaf.Raw[1] = marker + 1
						cert.SupportedSignatureAlgorithms[0] = algorithm
						cert.OCSPStaple[0] = marker + 2
						cert.SignedCertificateTimestamps[0][0] = marker + 3
					}
					certs := []*tls.Certificate{caller, &factoryCert, result.BindingCertificate}
					markers := []byte{0x11, 0x22, 0x33}
					algorithms := []tls.SignatureScheme{tls.PKCS1WithSHA384, tls.PSSWithSHA256, tls.PSSWithSHA384}
					var wg sync.WaitGroup
					for i, cert := range certs {
						wg.Add(1)
						go func(cert *tls.Certificate, marker byte, algorithm tls.SignatureScheme) {
							defer wg.Done()
							mutate(cert, marker, algorithm)
						}(cert, markers[i], algorithms[i])
					}
					wg.Wait()

					for i, cert := range certs {
						if cert.Certificate[0][0] != markers[i] ||
							cert.Leaf.Raw[1] != markers[i]+1 ||
							cert.SupportedSignatureAlgorithms[0] != algorithms[i] ||
							cert.OCSPStaple[0] != markers[i]+2 ||
							cert.SignedCertificateTimestamps[0][0] != markers[i]+3 {
							t.Errorf("certificate %d shares mutable state across an ownership boundary", i)
						}
					}
					if caller.PrivateKey != factoryCert.PrivateKey || caller.PrivateKey != result.BindingCertificate.PrivateKey {
						t.Error("PrivateKey should be the one intentionally shared field")
					}
				})
				seed, err := client.AcquireTokenByAuthCode(context.Background(), "code", "https://localhost", tokenScope)
				if err != nil {
					t.Fatal(err)
				}

				var refreshURL string
				var refreshRequestID string
				var refreshForm url.Values
				mockClient.AppendResponse(
					mock.WithBody(mock.GetAccessTokenBody("refreshed", idToken, "refresh-token", clientInfo, 3600, 0)),
					mock.WithCallback(func(r *http.Request) {
						refreshURL = r.URL.String()
						refreshRequestID = r.Header.Get("client-request-id")
						body, _ := io.ReadAll(r.Body)
						refreshForm, _ = url.ParseQuery(string(body))
					}),
				)
				if _, err := client.AcquireTokenSilent(context.Background(), tokenScope, WithSilentAccount(seed.Account)); err != nil {
					t.Fatal(err)
				}
				if got := refreshForm.Get("grant_type"); got != "refresh_token" {
					t.Fatalf("grant_type = %q, want refresh_token", got)
				}
				if got := refreshForm.Get("client_assertion_type"); !strings.HasSuffix(got, "jwt-pop") {
					t.Errorf("client_assertion_type = %q, want jwt-pop", got)
				}
				if len(callbackOptions) != 2 ||
					callbackOptions[1].TokenEndpoint != refreshURL ||
					callbackOptions[1].CorrelationID != refreshRequestID {
					t.Errorf("refresh callback options = %+v, request URI = %q, client-request-id = %q", callbackOptions, refreshURL, refreshRequestID)
				}
			})
			if test.private {
				opts = append(opts, WithInstanceDiscovery(false))
			}
			opts = append(opts, WithClientCapabilities([]string{"CP1"}))
			client, router := newBearerMtlsClient(t, cred, test.authority, opts...)
			if _, err := client.AcquireTokenByCredential(context.Background(), tokenScope,
				WithClaims(claims), WithFMIPath("fmi/path")); err != nil {
				t.Fatal(err)
			}
			req := router.tokenRequest()
			if req == nil {
				t.Fatal("no token request was sent")
			}
			if req.String() != test.want || got.TokenEndpoint != req.String() {
				t.Fatalf("callback endpoint = %q, request endpoint = %q, want %q", got.TokenEndpoint, req, test.want)
			}
			if got.ClientID != fakeClientID || got.TenantID != "tenant" {
				t.Errorf("callback identity options = {ClientID:%q TenantID:%q}", got.ClientID, got.TenantID)
			}
			if got.Authority != test.authority+"/" {
				t.Errorf("callback Authority = %q, want %q", got.Authority, test.authority+"/")
			}
			if got.Claims != claims || got.FMIPath != "fmi/path" {
				t.Errorf("callback request options = {Claims:%q FMIPath:%q}", got.Claims, got.FMIPath)
			}
			if !reflect.DeepEqual(got.ClientCapabilities, []string{"CP1"}) {
				t.Errorf("callback ClientCapabilities = %v, want [CP1]", got.ClientCapabilities)
			}
			if got.CorrelationID == "" {
				t.Error("callback CorrelationID is empty")
			} else if requestID := router.tokenRequestHeader().Get("client-request-id"); requestID != got.CorrelationID {
				t.Errorf("token request client-request-id = %q, callback CorrelationID = %q", requestID, got.CorrelationID)
			}
			if assertionType := router.tokenRequestBody().Get("client_assertion_type"); !strings.HasSuffix(assertionType, "jwt-pop") {
				t.Errorf("client_assertion_type = %q, want jwt-pop", assertionType)
			}
		})
	}
}

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
