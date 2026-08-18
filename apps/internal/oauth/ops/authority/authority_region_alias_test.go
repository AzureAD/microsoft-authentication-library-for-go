// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"context"
	"strings"
	"testing"
)

// TestRegionalDiscoveryUsesTheUnnormalizedAlias documents a PRE-EXISTING divergence in the instance
// discovery layer. It is deliberately NOT fixed here: it predates mTLS proof-of-possession, it
// affects the ordinary bearer path just as much, and changing which host regional discovery emits is
// a behavior change for every sovereign-cloud caller using WithAzureRegion. This test pins the
// current behavior so the divergence is visible and a future fix is a deliberate, reviewed change
// rather than an accident.
//
// login.usgovcloudapi.net is a legacy alias whose preferred network host is login.microsoftonline.us
// (see GetKnownMetadata). AADInstanceDiscovery regionalizes authorityInfo.Host verbatim, so with a
// region configured it produces {region}.login.usgovcloudapi.net. It does normalize the four public
// cloud hosts to login.microsoft.com for the tenant discovery endpoint, but the sovereign aliases get
// no such treatment, and even for the public hosts PreferredNetwork keeps the un-normalized host.
// MSAL .NET regionalizes the preferred network host instead.
//
// The mTLS endpoint derivation added by this PR does NOT have the bug - MtlsTokenEndpoint resolves
// the alias through GetKnownMetadata before the login -> mtlsauth swap, so it lands on
// {region}.mtlsauth.microsoftonline.us. The second half of this test pins that difference explicitly,
// so nobody later "fixes" the mTLS path to match the discovery path's behavior.
func TestRegionalDiscoveryUsesTheUnnormalizedAlias(t *testing.T) {
	const (
		alias     = "login.usgovcloudapi.net"
		preferred = "login.microsoftonline.us"
		region    = "usgovvirginia"
		tenant    = "contoso.onmicrosoft.us"
	)

	info := Info{Host: alias, Tenant: tenant, Region: region}

	// A region short-circuits the network call, so no Comm is needed.
	resp, err := (Client{}).AADInstanceDiscovery(context.Background(), info)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Metadata) != 1 {
		t.Fatalf("got %d metadata entries, want 1", len(resp.Metadata))
	}

	// Current behavior: the alias is regionalized as-is.
	wantNetwork := region + "." + alias
	if got := resp.Metadata[0].PreferredNetwork; got != wantNetwork {
		t.Errorf("PreferredNetwork = %q, want %q (current behavior; see the divergence note above)", got, wantNetwork)
	}
	if !strings.Contains(resp.TenantDiscoveryEndpoint, wantNetwork) {
		t.Errorf("TenantDiscoveryEndpoint = %q, want it to contain %q", resp.TenantDiscoveryEndpoint, wantNetwork)
	}
	// Spelled out so the divergence cannot be misread as "Go normalizes it".
	if strings.Contains(resp.Metadata[0].PreferredNetwork, preferred) {
		t.Errorf("PreferredNetwork = %q unexpectedly normalized to %q; the divergence this test documents "+
			"has been fixed, so update the test and the note", resp.Metadata[0].PreferredNetwork, preferred)
	}

	// The mTLS path normalizes first, so it does not inherit the divergence.
	endpoint, err := (AuthParams{AuthorityInfo: info}).MtlsTokenEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	wantMtls := "https://" + region + ".mtlsauth.microsoftonline.us/" + tenant + "/oauth2/v2.0/token"
	if endpoint != wantMtls {
		t.Errorf("MtlsTokenEndpoint() = %q, want %q", endpoint, wantMtls)
	}
}
