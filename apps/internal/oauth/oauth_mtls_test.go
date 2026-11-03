// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package oauth

import (
	"context"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

type fixedEndpointResolver struct {
	endpoints authority.Endpoints
}

func (r fixedEndpointResolver) ResolveEndpoints(context.Context, authority.Info, string) (authority.Endpoints, error) {
	return r.endpoints, nil
}

func TestResolveTokenEndpointSkipsRegionDiscoveryForDSTS(t *testing.T) {
	t.Setenv("REGION_NAME", "westus2")
	const endpoint = "https://dsts.core.windows.net/dstsv2/tenant/oauth2/v2.0/token"
	client := Client{Resolver: fixedEndpointResolver{endpoints: authority.NewEndpoints("", endpoint, "", "")}}
	params := authority.AuthParams{
		AuthorityInfo: authority.Info{
			Host:                  "dsts.core.windows.net",
			CanonicalAuthorityURI: "https://dsts.core.windows.net/dstsv2/tenant/",
			AuthorityType:         authority.DSTS,
			Tenant:                authority.DSTSTenant,
			Region:                "TryAutoDetect",
		},
		IsMtlsPoP: true,
	}
	if err := client.ResolveTokenEndpoint(context.Background(), &params); err != nil {
		t.Fatal(err)
	}
	if params.AuthorityInfo.Region != "TryAutoDetect" {
		t.Fatalf("dSTS region = %q; auto-discovery should have been skipped", params.AuthorityInfo.Region)
	}
	if params.TokenEndpoint != endpoint {
		t.Fatalf("dSTS final endpoint = %q, want unchanged %q", params.TokenEndpoint, endpoint)
	}
}
