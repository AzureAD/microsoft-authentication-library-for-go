// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// countingClient records every request it is asked to make and refuses to make any, so a test can
// assert that validation happened before the network was touched.
type countingClient struct{ calls int32 }

func (c *countingClient) Do(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&c.calls, 1)
	return nil, fmt.Errorf("unexpected network call to %s", req.URL)
}

func (c *countingClient) CloseIdleConnections() {}

func (c *countingClient) count() int { return int(atomic.LoadInt32(&c.calls)) }

// TestMtlsPoPValidatesAuthorityBeforeNetwork covers the hoisted authority check. The mTLS authority
// contract used to be enforced only while deriving the token endpoint, which runs during the HTTP
// call, so an unsupported authority survived credential resolution, the silent cache lookup and
// endpoint discovery before being rejected on the network. MSAL .NET validates during parameter
// initialization (MtlsPopParametersInitializer), before any cache or discovery work.
func TestMtlsPoPValidatesAuthorityBeforeNetwork(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		desc      string
		authority string
		wantErr   string
	}{
		{
			desc:      "common",
			authority: "https://login.microsoftonline.com/common",
			wantErr:   "requires a tenanted authority",
		},
		{
			desc:      "organizations",
			authority: "https://login.microsoftonline.com/organizations",
			wantErr:   "requires a tenanted authority",
		},
		{
			desc:      "consumers",
			authority: "https://login.microsoftonline.com/consumers",
			wantErr:   "requires a tenanted authority",
		},
		{
			desc:      "unsupported host",
			authority: "https://sts.windows.net/tenant",
			wantErr:   "a login.* host is required",
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			counter := &countingClient{}
			client, err := New(test.authority, fakeClientID, cred, WithHTTPClient(counter))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
			if err == nil {
				t.Fatal("AcquireTokenByCredential = nil error, want the authority to be rejected")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, test.wantErr)
			}
			if n := counter.count(); n != 0 {
				t.Errorf("the authority was rejected only after %d network call(s); validation must happen first", n)
			}
		})
	}
}

// TestMtlsPoPCredentialErrorWinsOverAuthorityError pins the ordering: the credential is resolved
// before the authority is validated, so a credential that can't present a client certificate reports
// that, not an authority error. MSAL .NET orders these the same way - ValidateAadAuthorityForPop runs
// after the credential provider in MtlsPopParametersInitializer, deliberately, so the public
// missing-certificate contract survives.
func TestMtlsPoPCredentialErrorWinsOverAuthorityError(t *testing.T) {
	secretCred, err := NewCredFromSecret("secret")
	if err != nil {
		t.Fatal(err)
	}
	counter := &countingClient{}
	// Both things are wrong: the credential can't produce a certificate AND the authority isn't
	// tenanted. The credential error must be the one reported.
	client, err := New("https://login.microsoftonline.com/common", fakeClientID, secretCred, WithHTTPClient(counter))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("AcquireTokenByCredential = nil error, want the credential to be rejected")
	}
	if !strings.Contains(err.Error(), "client secret") {
		t.Errorf("error = %q, want the missing-certificate contract to be preserved for a secret credential", err)
	}
	if strings.Contains(err.Error(), "tenanted authority") {
		t.Errorf("error = %q, want the credential error rather than the authority error", err)
	}
	if n := counter.count(); n != 0 {
		t.Errorf("the request was rejected only after %d network call(s)", n)
	}
}

// TestMtlsPoPAuthorityValidationStillGuardsTheNetworkPath pins that hoisting the check did not leave
// the token request unguarded: MtlsTokenEndpoint still refuses an authority that reaches it, so
// another entry point can't skip the contract.
func TestMtlsPoPAuthorityValidationStillGuardsTheNetworkPath(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New("https://login.microsoftonline.com/tenant", fakeClientID, cred)
	if err != nil {
		t.Fatal(err)
	}
	// Reach past the option layer the way the token request does, with an authority that the early
	// check would have rejected.
	authParams := client.base.AuthParams
	authParams.AuthorityInfo.Tenant = "common"
	if _, err := authParams.MtlsTokenEndpoint(); err == nil {
		t.Error("MtlsTokenEndpoint accepted a non-tenanted authority; the network path is unguarded")
	} else if !strings.Contains(err.Error(), "requires a tenanted authority") {
		t.Errorf("error = %q, want the tenanted-authority message", err)
	}

	authParams = client.base.AuthParams
	authParams.AuthorityInfo.Host = "sts.windows.net"
	if _, err := authParams.MtlsTokenEndpoint(); err == nil {
		t.Error("MtlsTokenEndpoint accepted an unsupported host; the network path is unguarded")
	}
}

// TestMtlsPoPTenantedAuthorityAccepted is the control: a valid tenanted login.* authority is not
// rejected by the new early check, so the guard can't pass simply by refusing everything. The
// request is allowed to reach the network, which the counting client then refuses.
func TestMtlsPoPTenantedAuthorityAccepted(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	counter := &countingClient{}
	client, err := New("https://login.microsoftonline.com/contoso.onmicrosoft.com", fakeClientID, cred, WithHTTPClient(counter))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("expected the counting client to refuse the request")
	}
	if strings.Contains(err.Error(), "mTLS proof-of-possession") && !errors.Is(err, context.Canceled) {
		t.Errorf("a valid tenanted authority was rejected by the mTLS contract check: %v", err)
	}
	if counter.count() == 0 {
		t.Error("a valid authority never reached the network, so the early check is over-rejecting")
	}
}

// unusableBindingCertCred returns a credential that passes validateMtlsCredential but fails binding-
// certificate resolution, and counts how many times its callback ran. It is a signed-assertion
// credential, so validateMtlsCredential accepts it (it is not a secret or a token provider, and a
// SignedAssertionCallback is allowed to stand in for an explicit certificate), but the certificate
// the callback hands back carries no chain, so validBindingCertificate rejects it. That places the
// only failure at certificate resolution, which is what the ordering tests below need.
//
// The alternative was a certificate credential with a corrupt x5c entry. This route was chosen
// because NewCredFromCert always writes well-formed base64, so the x5c variant would have to
// fabricate an internal Credential state the public API cannot produce; this one is built entirely
// through the public API, and it fails with a message that names the certificate explicitly rather
// than an opaque base64 decoding error.
func unusableBindingCertCred(invoked *int32) Credential {
	return NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
		atomic.AddInt32(invoked, 1)
		// Non-nil, so resolution reaches validBindingCertificate rather than falling through to the
		// "no certificate credential" path, but empty, so it is rejected there.
		return SignedAssertion{Assertion: "assertion", BindingCertificate: &tls.Certificate{}}, nil
	})
}

// TestMtlsPoPBindingCertErrorSurfacesOnASupportedAuthority is the premise for the test below: it
// proves unusableBindingCertCred really does fail certificate resolution, so the double-fault test
// cannot pass vacuously. With a supported authority nothing rejects the request early, so it reaches
// the callback and is then rejected by validBindingCertificate.
func TestMtlsPoPBindingCertErrorSurfacesOnASupportedAuthority(t *testing.T) {
	var invoked int32
	lmo, tenant := "login.microsoftonline.com", "tenant"
	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, unusableBindingCertCred(&invoked),
		WithHTTPClient(discoveryClient{host: lmo, tenant: tenant}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("AcquireTokenByCredential = nil error, want the binding certificate to be rejected")
	}
	if !strings.Contains(err.Error(), "unusable binding certificate") {
		t.Errorf("error = %q, want the binding-certificate error; without it the ordering test below proves nothing", err)
	}
	if n := atomic.LoadInt32(&invoked); n != 1 {
		t.Errorf("signed-assertion callback invoked %d times, want 1", n)
	}
}

// TestMtlsPoPAuthorityErrorWinsOverBindingCertError pins the one place this branch deliberately
// diverges from its parent (#632); see the comment at the ValidateMtlsPoP call in
// AcquireTokenByCredential for the rationale.
//
// Both faults are present at once: the authority is not a supported mTLS PoP authority AND the
// credential cannot produce a usable binding certificate. #632 resolves the certificate before
// validating the authority, so it reports the certificate error. Here the authority is validated
// first, so it reports the authority error.
//
// The reason for the difference is the second assertion, not the first. On this branch certificate
// resolution happens inside prepareMtlsPoP, behind ResolveEndpoints and the signed-assertion
// callback, both of which touch the network; #632's is network-free. Resolving the certificate first
// would therefore mean doing network work before the authority contract is checked. Rejecting the
// authority first is what keeps the request count at zero, and that is the property worth having.
//
// Restoring #632's order by moving ValidateMtlsPoP after prepareMtlsPoP fails both assertions: the
// surfaced error becomes an endpoint-resolution failure and the counting client records a request.
func TestMtlsPoPAuthorityErrorWinsOverBindingCertError(t *testing.T) {
	for _, test := range []struct {
		desc      string
		authority string
		wantErr   string
	}{
		{
			desc:      "non-tenanted authority",
			authority: "https://login.microsoftonline.com/common",
			wantErr:   "requires a tenanted authority",
		},
		{
			desc:      "unsupported host",
			authority: "https://sts.windows.net/tenant",
			wantErr:   "a login.* host is required",
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			var invoked int32
			counter := &countingClient{}
			client, err := New(test.authority, fakeClientID, unusableBindingCertCred(&invoked), WithHTTPClient(counter))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
			if err == nil {
				t.Fatal("AcquireTokenByCredential = nil error, want the authority to be rejected")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("error = %q, want the authority error %q to be the one that surfaces", err, test.wantErr)
			}
			if strings.Contains(err.Error(), "binding certificate") {
				t.Errorf("error = %q, want the authority error rather than the binding-certificate error", err)
			}
			// The half that is the reason for the ordering: certificate resolution sits behind
			// endpoint resolution and the callback, so validating the authority first is what stops
			// an invalid authority from costing a network round trip.
			if n := counter.count(); n != 0 {
				t.Errorf("the authority was rejected only after %d network call(s); it must be rejected before any", n)
			}
			if n := atomic.LoadInt32(&invoked); n != 0 {
				t.Errorf("the signed-assertion callback ran %d times; an invalid authority must be rejected before the credential's callback has any effect", n)
			}
		})
	}
}
