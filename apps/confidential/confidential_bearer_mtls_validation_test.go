// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

// The authority every case in this file starts from: trusted host, AAD authority type, tenanted.
// The positive control uses it unchanged, so each rejection case can vary exactly one thing away
// from it and attribute the rejection to that one difference.
const bearerMtlsControlAuthority = "https://login.microsoftonline.com/contoso.onmicrosoft.com"

// bearerMtlsRouter answers discovery from canned bodies and records any request that is neither
// instance nor tenant discovery - which, on this path, can only be the token request.
//
// It routes on the request URL instead of returning canned responses in order, because these cases
// do not all make the same discovery calls: instance discovery runs for some authorities and not
// others, so a positional mock would hand a discovery body to the wrong request and the resulting
// failure would look like a guard failure. Routing keeps every case honest about what it proves.
type bearerMtlsRouter struct {
	host   string
	tenant string

	mu        sync.Mutex
	tokenReqs []*url.URL
}

func (r *bearerMtlsRouter) Do(req *http.Request) (*http.Response, error) {
	var body []byte
	switch path := req.URL.Path; {
	case strings.Contains(path, "/discovery/instance"):
		body = mock.GetInstanceDiscoveryBody(r.host, r.tenant)
	case strings.Contains(path, ".well-known/openid-configuration"):
		body = mock.GetTenantDiscoveryBody(r.host, r.tenant)
	default:
		r.mu.Lock()
		r.tokenReqs = append(r.tokenReqs, req.URL)
		r.mu.Unlock()
		body = mock.GetAccessTokenBody("bearer-over-mtls-token", "", "", "", 3600, 0)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}, nil
}

func (r *bearerMtlsRouter) CloseIdleConnections() {}

// tokenRequest returns the first token request that was sent, or nil if none was.
func (r *bearerMtlsRouter) tokenRequest() *url.URL {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.tokenReqs) == 0 {
		return nil
	}
	return r.tokenReqs[0]
}

type bearerMtlsRoundTripper struct{ router *bearerMtlsRouter }

func (t bearerMtlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.router.Do(req)
}

// routerMtlsFactory supplies the same router as the mutual-TLS client, so the token request is
// recorded whichever transport carries it.
func routerMtlsFactory(r *bearerMtlsRouter) func(tls.Certificate) *http.Client {
	return func(tls.Certificate) *http.Client {
		return &http.Client{Transport: bearerMtlsRoundTripper{router: r}}
	}
}

// newBearerMtlsClient builds a Bearer-over-mTLS client for the given authority through the public
// option, so the authority is parsed by NewInfoFromAuthorityURI exactly as a real caller's would be
// rather than assembled as an authority.Info literal.
func newBearerMtlsClient(t *testing.T, cred Credential, authorityURI string, extra ...Option) (Client, *bearerMtlsRouter) {
	t.Helper()
	u, err := url.Parse(authorityURI)
	if err != nil {
		t.Fatal(err)
	}
	router := &bearerMtlsRouter{host: u.Host, tenant: strings.Trim(u.Path, "/")}
	opts := append([]Option{
		WithHTTPClient(router),
		WithMtlsHTTPClient(routerMtlsFactory(router)),
		WithSendCertificateOverMtls(),
	}, extra...)
	client, err := New(authorityURI, fakeClientID, cred, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return client, router
}

// Bearer-over-mTLS reaches the same authority guards as mTLS PoP, but by a different route and with
// different timing. accesstokens.doTokenResp routes on `IsMtlsPoP || MtlsTransport`, and both go
// through AuthParams.MtlsTokenEndpoint, which calls ValidateMtlsPoP. Unlike the PoP path there is no
// early check in confidential.go, so the bearer path is validated while the token endpoint is being
// derived - after endpoint discovery, immediately before the token request would be sent.
//
// That timing is why these cases do not use countingClient the way the PoP tests do: discovery has
// to be allowed to succeed for the request to reach the guard at all. Each case instead asserts the
// token request itself never went out, which is the bearer-path equivalent of "rejected before the
// network call that matters".
//
// None of these use WithMtlsProofOfPossession. They are plain Bearer callers that only asked for the
// mutual-TLS transport, which is precisely the combination that had no coverage.
func TestSendCertificateOverMtls_ValidatesAuthority(t *testing.T) {
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
			// Varies from the control only in the tenant: "common" rather than a real tenant.
			desc:      "common",
			authority: "https://login.microsoftonline.com/common",
			wantErr:   "requires a tenanted authority",
		},
		{
			// Varies from the control only in the tenant.
			desc:      "organizations",
			authority: "https://login.microsoftonline.com/organizations",
			wantErr:   "requires a tenanted authority",
		},
		{
			// Varies from the control only in the tenant.
			desc:      "consumers",
			authority: "https://login.microsoftonline.com/consumers",
			wantErr:   "requires a tenanted authority",
		},
		{
			// Varies from the control only in the first path segment, which is what decides
			// AuthorityType. The host is still the trusted login.microsoftonline.com, so this is
			// rejected on authority type alone rather than by the host guard.
			desc:      "ADFS on a login.* host",
			authority: "https://login.microsoftonline.com/adfs",
			wantErr:   `authority type "ADFS"`,
		},
		{
			// As above, only the first path segment differs from the control.
			desc:      "dSTS on a login.* host",
			authority: "https://login.microsoftonline.com/dstsv2/" + authority.DSTSTenant,
			wantErr:   `authority type "DSTS"`,
		},
		{
			// Varies from the control only in the host. Bearer-over-mTLS still presents the binding
			// certificate to the derived mtlsauth.* host, and forces x5c onto the client assertion,
			// so an untrusted host must not be rewritten here either.
			desc:      "untrusted login.* host",
			authority: "https://login.evil.test/contoso.onmicrosoft.com",
			wantErr:   "not a known Microsoft cloud host",
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			client, router := newBearerMtlsClient(t, cred, test.authority)

			_, err := client.AcquireTokenByCredential(context.Background(), tokenScope)
			if err == nil {
				t.Fatal("AcquireTokenByCredential = nil error, want the authority to be rejected on the bearer-over-mTLS path")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, test.wantErr)
			}
			if got := router.tokenRequest(); got != nil {
				t.Errorf("a token request was sent to %s; the authority must be rejected before the token request goes out", got)
			}
		})
	}
}

// TestSendCertificateOverMtls_AuthorityTypeGuardNamesAAD pins the guard ae7f3c5 added, separately
// from the "contains ADFS" assertion above: the rejection names the authority type that is required.
// Built from the authority.AAD constant rather than its literal value, so the assertion keeps
// meaning the same thing if that value ever changes.
func TestSendCertificateOverMtls_AuthorityTypeGuardNamesAAD(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	client, router := newBearerMtlsClient(t, cred, "https://login.microsoftonline.com/adfs")

	_, err = client.AcquireTokenByCredential(context.Background(), tokenScope)
	if err == nil {
		t.Fatal("AcquireTokenByCredential = nil error, want a non-AAD authority to be rejected")
	}
	if want := fmt.Sprintf("an AAD (%s) authority is required", authority.AAD); !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to contain %q", err, want)
	}
	if got := router.tokenRequest(); got != nil {
		t.Errorf("a token request was sent to %s; a non-AAD authority must never reach the token endpoint", got)
	}
}

// TestSendCertificateOverMtls_TrustedTenantedAuthorityAccepted is the positive control for this
// file. Without it the rejection cases cannot distinguish "the guard rejected this authority" from
// "bearer-over-mTLS is broken and rejects everything". Same credential, same options and same call
// as the rejection cases - only the authority is the untouched control - and here the token request
// is expected to go out, to the derived mtlsauth host.
func TestSendCertificateOverMtls_TrustedTenantedAuthorityAccepted(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	client, router := newBearerMtlsClient(t, cred, bearerMtlsControlAuthority)

	res, err := client.AcquireTokenByCredential(context.Background(), tokenScope)
	if err != nil {
		t.Fatalf("the control authority was rejected on the bearer-over-mTLS path: %v", err)
	}
	if res.AccessToken != "bearer-over-mtls-token" {
		t.Errorf("AccessToken = %q, want bearer-over-mtls-token", res.AccessToken)
	}
	got := router.tokenRequest()
	if got == nil {
		t.Fatal("the control authority never reached the token endpoint, so the guards are over-rejecting")
	}
	if got.Host != "mtlsauth.microsoft.com" {
		t.Errorf("token endpoint host = %q, want mtlsauth.microsoft.com", got.Host)
	}
}

// TestSendCertificateOverMtls_PrivateCloudOptInIsHonored is the counterpart control to the
// untrusted-host rejection above, mirroring TestMtlsPoPPrivateCloudOptInIsHonored for the bearer
// path. Exactly one option differs from that rejection case - WithInstanceDiscovery(false) - so the
// host-trust guard is shown to gate on the caller's explicit private-cloud trust decision rather
// than refusing every host outside the static list.
func TestSendCertificateOverMtls_PrivateCloudOptInIsHonored(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	client, router := newBearerMtlsClient(t, cred,
		"https://login.contoso.internal/contoso.onmicrosoft.com", WithInstanceDiscovery(false))

	if _, err := client.AcquireTokenByCredential(context.Background(), tokenScope); err != nil {
		t.Fatalf("a private cloud that opted out of instance discovery was rejected on the bearer-over-mTLS path: %v", err)
	}
	got := router.tokenRequest()
	if got == nil {
		t.Fatal("the opted-in private cloud never reached the token endpoint")
	}
	// The opted-in caller derives its own private mtlsauth host, not a Microsoft one.
	if got.Host != "mtlsauth.contoso.internal" {
		t.Errorf("token endpoint host = %q, want mtlsauth.contoso.internal", got.Host)
	}
}
