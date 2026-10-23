// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"context"
	"testing"
)

// TestRegionalDiscoveryAndMtlsNormalizeAlias verifies that discovery and mTLS
// both resolve a legacy sovereign alias before regionalizing the endpoint.
func TestRegionalDiscoveryAndMtlsNormalizeAlias(t *testing.T) {
	const (
		alias     = "login.usgovcloudapi.net"
		preferred = "login.microsoftonline.us"
		region    = "usgovvirginia"
		tenant    = "contoso.onmicrosoft.us"
	)

	info := Info{Host: alias, Tenant: tenant, Region: region, AuthorityType: AAD}

	// A region short-circuits the network call, so no Comm is needed.
	resp, err := (Client{}).AADInstanceDiscovery(context.Background(), info)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Metadata) != 1 {
		t.Fatalf("got %d metadata entries, want 1", len(resp.Metadata))
	}

	wantNetwork := region + "." + preferred
	if got := resp.Metadata[0].PreferredNetwork; got != wantNetwork {
		t.Errorf("PreferredNetwork = %q, want %q", got, wantNetwork)
	}
	wantDiscovery := "https://" + wantNetwork + "/" + tenant + "/v2.0/.well-known/openid-configuration"
	if got := resp.TenantDiscoveryEndpoint; got != wantDiscovery {
		t.Errorf("TenantDiscoveryEndpoint = %q, want %q", got, wantDiscovery)
	}

	endpoint, err := (AuthParams{AuthorityInfo: info}).MtlsTokenEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	wantMtls := "https://" + region + ".mtlsauth.microsoftonline.us/" + tenant + "/oauth2/v2.0/token"
	if endpoint != wantMtls {
		t.Errorf("MtlsTokenEndpoint() = %q, want %q", endpoint, wantMtls)
	}
}
