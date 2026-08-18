// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
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
