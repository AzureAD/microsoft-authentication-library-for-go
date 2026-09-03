// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
)

// Regression test for https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/663
//
// ResolveEndpoints caches the discovered endpoints before it validates that the
// issuer matches the authority. When validation rejects the response the call
// returns an error, but the cache entry is left behind. The next call for the
// same authority is served from that cache, and the cache lookup happens before
// any validation runs, so the rejected endpoints are returned to the caller.
//
// Contract under test: an issuer that is rejected once must stay rejected.
//
// This test is EXPECTED TO FAIL on main. It is pushed to demonstrate the defect
// in CI. It is not a proposed fix.
func TestIssue663_IssuerValidationIsNotBypassedByCache(t *testing.T) {
	var httpCalls int32

	// Serves an issuer that fails every acceptance rule in
	// ValidateIssuerMatchesAuthority: it is not an exact scheme+host match, it is
	// not a trusted AAD host, and the authority (127.0.0.1:port) is not a
	// subdomain of it. Every call must therefore be rejected.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&httpCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"authorization_endpoint": "https://attacker.example.com/common/oauth2/v2.0/authorize",
			"token_endpoint": "https://attacker.example.com/common/oauth2/v2.0/token",
			"issuer": "https://attacker.example.com/common/v2.0"
		}`)
	}))
	defer srv.Close()

	resolver := newAuthorityEndpoint(ops.New(srv.Client()))
	info := newTestAuthorityInfo("login.microsoftonline.com", srv.URL+"/common/", "common")

	// First call: the mismatched issuer must be rejected.
	if _, err := resolver.ResolveEndpoints(context.Background(), info, ""); err == nil {
		t.Fatal("first call: expected the mismatched issuer to be rejected, got nil")
	} else if !strings.Contains(err.Error(), "does not match authority") {
		t.Fatalf("first call: rejected for an unexpected reason: %v", err)
	}

	// Second call: identical input, so it must be rejected identically.
	endpoints, err := resolver.ResolveEndpoints(context.Background(), info, "")
	if err == nil {
		t.Errorf("second call returned endpoints for an issuer that was just rejected.\n"+
			"  TokenEndpoint         = %s\n"+
			"  AuthorizationEndpoint = %s\n"+
			"  HTTP calls to the discovery server = %d\n"+
			"A count of 1 means the second call was served from the cache rather than the\n"+
			"network, so issuer validation never ran. The endpoints were cached before\n"+
			"validation and were not removed when validation failed.",
			endpoints.TokenEndpoint, endpoints.AuthorizationEndpoint, atomic.LoadInt32(&httpCalls))
	}
}

// Companion check: after a rejected resolution nothing may remain cached, so a
// later valid response must be fetched from the network and honored.
//
// This test is EXPECTED TO FAIL on main.
func TestIssue663_RejectedResolutionLeavesNothingCached(t *testing.T) {
	var httpCalls int32

	// First response has a mismatched issuer and must be rejected. Every later
	// response is valid and must be accepted.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&httpCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			fmt.Fprint(w, `{
				"authorization_endpoint": "https://attacker.example.com/common/oauth2/v2.0/authorize",
				"token_endpoint": "https://attacker.example.com/common/oauth2/v2.0/token",
				"issuer": "https://attacker.example.com/common/v2.0"
			}`)
			return
		}
		fmt.Fprint(w, tenantDiscoveryJSON("login.microsoftonline.com"))
	}))
	defer srv.Close()

	resolver := newAuthorityEndpoint(ops.New(srv.Client()))
	info := newTestAuthorityInfo("login.microsoftonline.com", srv.URL+"/common/", "common")

	if _, err := resolver.ResolveEndpoints(context.Background(), info, ""); err == nil {
		t.Fatal("first call: expected the mismatched issuer to be rejected, got nil")
	}

	endpoints, err := resolver.ResolveEndpoints(context.Background(), info, "")
	if err != nil {
		t.Fatalf("second call: unexpected error: %v", err)
	}

	if strings.Contains(endpoints.TokenEndpoint, "attacker.example.com") {
		t.Errorf("second call returned the rejected endpoints instead of re-resolving.\n"+
			"  TokenEndpoint = %s\n"+
			"  HTTP calls to the discovery server = %d\n"+
			"This mirrors the contract asserted by TestResolveEndpoints_ErrorNotCached,\n"+
			"which passes only because it exercises an HTTP-level failure. That path\n"+
			"returns before the cache write, while issuer validation runs after it.",
			endpoints.TokenEndpoint, atomic.LoadInt32(&httpCalls))
	}
}
