// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

// TestMtlsPoPDSTSKeepsItsEndpointAndCaches is the end-to-end counterpart to
// TestMtlsTokenEndpointAcceptsTenantedDSTS: a tenanted dSTS authority acquires an mTLS PoP token
// through the public API, the request goes to the authority's own token endpoint rather than an
// mtlsauth.* rewrite, and the result is cached and served from cache on the next call.
//
// A unit test on MtlsTokenEndpoint alone would not catch a client-level guard rejecting dSTS before
// the endpoint is ever computed, which is exactly what the previous authority-type gate did.
//
// The cache assertion is load-bearing rather than incidental: the mTLS PoP cache key is partitioned
// by the binding certificate's x5t#S256, and the token is keyed under the authority MSAL resolved.
// If the dSTS path ever wrote under one identity and read under another, every acquisition would
// silently miss and hit the network - which is a correctness and rate-limit problem, not a
// performance one. The mock panics when its queue is empty, so a second network call would fail the
// test rather than pass it quietly.
func TestMtlsPoPDSTSKeepsItsEndpointAndCaches(t *testing.T) {
	cred := newBindingCertCred(t, "dsts-binding-cert", 42)

	host := "dsts.core.windows.net"
	tenantPath := "dstsv2/" + authority.DSTSTenant
	authorityURI := fmt.Sprintf("https://%s/%s", host, tenantPath)

	mockClient := mock.NewClient()
	var tokenURLs []*url.URL
	// Tenant discovery supplies the token endpoint that dSTS must keep verbatim. Instance discovery
	// is disabled: it is an AAD concept and this authority is not in AAD's metadata.
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(host, tenantPath)))
	mockClient.AppendResponse(
		mock.WithBody(mtlsPoPTokenBody("dsts-mtls-pop-token", 3600)),
		mock.WithCallback(func(r *http.Request) { tokenURLs = append(tokenURLs, r.URL) }),
	)

	cache := make(testCache)
	client, err := New(authorityURI, fakeClientID, cred,
		WithCache(&cache),
		WithHTTPClient(mockClient),
		WithMtlsHTTPClient(mockMtlsFactory(mockClient)),
		WithInstanceDiscovery(false),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	res, err := client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("dSTS mTLS PoP acquisition failed: %v", err)
	}
	if res.AccessToken != "dsts-mtls-pop-token" {
		t.Errorf("AccessToken = %q, want the token the endpoint returned", res.AccessToken)
	}
	if res.BindingCertificate == nil {
		t.Error("AuthResult.BindingCertificate is nil; an mTLS PoP result must carry the certificate the token is bound to")
	}

	if len(tokenURLs) != 1 {
		t.Fatalf("the token endpoint was called %d times, want exactly 1", len(tokenURLs))
	}
	wantEndpoint := authorityURI + "/oauth2/v2.0/token"
	if got := tokenURLs[0].String(); got != wantEndpoint {
		t.Errorf("token request went to %q, want the authority's own endpoint %q", got, wantEndpoint)
	}
	if strings.Contains(tokenURLs[0].Host, "mtlsauth.") {
		t.Errorf("token request went to %q; a dSTS authority must not be rewritten to mtlsauth.*", tokenURLs[0].Host)
	}

	// Cache hit. No response is queued, so a network call here panics the mock.
	// AcquireTokenByCredential checks the cache before the network, and it is the entry point that
	// accepts WithMtlsProofOfPossession; the PoP option is not an AcquireTokenSilent option, so the
	// silent path cannot express this request.
	cached, err := client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("the dSTS mTLS PoP token was not served from the cache: %v", err)
	}
	if cached.AccessToken != res.AccessToken {
		t.Errorf("cached AccessToken = %q, want %q", cached.AccessToken, res.AccessToken)
	}
	if len(tokenURLs) != 1 {
		t.Errorf("the token endpoint was called %d times in total, want 1; the second acquisition should have been a cache hit", len(tokenURLs))
	}
}

// TestMtlsPoPDSTSRegionDoesNotRegionalizeTheEndpoint pins that configuring a region alongside a dSTS
// authority does not move the token request. Region builds <region>.<host> on the AAD path only; a
// regionalized dSTS host would not resolve, and the failure would surface as a transport error far
// from its cause.
func TestMtlsPoPDSTSRegionDoesNotRegionalizeTheEndpoint(t *testing.T) {
	cred := newBindingCertCred(t, "dsts-regional-binding-cert", 43)

	host := "dsts.core.windows.net"
	tenantPath := "dstsv2/" + authority.DSTSTenant
	authorityURI := fmt.Sprintf("https://%s/%s", host, tenantPath)

	mockClient := mock.NewClient()
	var tokenURLs []*url.URL
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(host, tenantPath)))
	mockClient.AppendResponse(
		mock.WithBody(mtlsPoPTokenBody("dsts-regional-token", 3600)),
		mock.WithCallback(func(r *http.Request) { tokenURLs = append(tokenURLs, r.URL) }),
	)

	client, err := New(authorityURI, fakeClientID, cred,
		WithHTTPClient(mockClient),
		WithMtlsHTTPClient(mockMtlsFactory(mockClient)),
		WithInstanceDiscovery(false),
		WithAzureRegion("westus"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("dSTS mTLS PoP acquisition with a region failed: %v", err)
	}
	if len(tokenURLs) != 1 {
		t.Fatalf("the token endpoint was called %d times, want exactly 1", len(tokenURLs))
	}
	if got := tokenURLs[0].Host; got != host {
		t.Errorf("token request Host = %q, want %q unchanged; a region must not regionalize a dSTS endpoint", got, host)
	}
}
