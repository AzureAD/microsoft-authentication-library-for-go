// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"testing"
)

// TestGetKnownMetadata verifies that GetKnownMetadata returns correct
// PreferredNetwork, PreferredCache, and alias lists for every host in the
// eight known cloud environments, and returns (_, false) for unknown hosts.
func TestGetKnownMetadata(t *testing.T) {
	tests := []struct {
		host           string
		wantOK         bool
		wantPreferred  string
		wantCache      string
		wantAliasCount int
	}{
		// Public Cloud hosts - all should return the same entry
		{"login.microsoftonline.com", true, "login.microsoftonline.com", "login.windows.net", 4},
		{"login.windows.net", true, "login.microsoftonline.com", "login.windows.net", 4},
		{"login.microsoft.com", true, "login.microsoftonline.com", "login.windows.net", 4},
		{"sts.windows.net", true, "login.microsoftonline.com", "login.windows.net", 4},
		// China Cloud
		{"login.partner.microsoftonline.cn", true, "login.partner.microsoftonline.cn", "login.partner.microsoftonline.cn", 2},
		{"login.chinacloudapi.cn", true, "login.partner.microsoftonline.cn", "login.partner.microsoftonline.cn", 2},
		// Germany Cloud (legacy)
		{"login.microsoftonline.de", true, "login.microsoftonline.de", "login.microsoftonline.de", 1},
		// US Government Cloud
		{"login.microsoftonline.us", true, "login.microsoftonline.us", "login.microsoftonline.us", 2},
		{"login.usgovcloudapi.net", true, "login.microsoftonline.us", "login.microsoftonline.us", 2},
		// US Regional
		{"login-us.microsoftonline.com", true, "login-us.microsoftonline.com", "login-us.microsoftonline.com", 1},
		// Sovereign clouds
		{"login.sovcloud-identity.fr", true, "login.sovcloud-identity.fr", "login.sovcloud-identity.fr", 1},
		{"login.sovcloud-identity.de", true, "login.sovcloud-identity.de", "login.sovcloud-identity.de", 1},
		{"login.sovcloud-identity.sg", true, "login.sovcloud-identity.sg", "login.sovcloud-identity.sg", 1},
		// Unknown hosts
		{"unknown.example.com", false, "", "", 0},
		{"malicious.example.com", false, "", "", 0},
	}

	for _, test := range tests {
		t.Run(test.host, func(t *testing.T) {
			md, ok := GetKnownMetadata(test.host)
			if ok != test.wantOK {
				t.Fatalf("GetKnownMetadata(%q) ok = %v, want %v", test.host, ok, test.wantOK)
			}
			if !ok {
				return
			}
			if md.PreferredNetwork != test.wantPreferred {
				t.Errorf("PreferredNetwork = %q, want %q", md.PreferredNetwork, test.wantPreferred)
			}
			if md.PreferredCache != test.wantCache {
				t.Errorf("PreferredCache = %q, want %q", md.PreferredCache, test.wantCache)
			}
			if len(md.Aliases) != test.wantAliasCount {
				t.Errorf("len(Aliases) = %d, want %d", len(md.Aliases), test.wantAliasCount)
			}
		})
	}
}

// TestPublicCloudAliasesShareEntry verifies that all four public cloud hosts
// (login.microsoftonline.com, login.windows.net, login.microsoft.com,
// sts.windows.net) return identical alias lists. This ensures cross-alias SSO
// works: a token cached under one host can be found when querying another.
func TestPublicCloudAliasesShareEntry(t *testing.T) {
	publicHosts := []string{
		"login.microsoftonline.com",
		"login.windows.net",
		"login.microsoft.com",
		"sts.windows.net",
	}
	var firstAliases []string
	for _, host := range publicHosts {
		md, ok := GetKnownMetadata(host)
		if !ok {
			t.Fatalf("GetKnownMetadata(%q) returned false", host)
		}
		if firstAliases == nil {
			firstAliases = md.Aliases
		} else {
			if len(md.Aliases) != len(firstAliases) {
				t.Errorf("host %q has %d aliases, expected %d", host, len(md.Aliases), len(firstAliases))
			}
			for i, a := range md.Aliases {
				if a != firstAliases[i] {
					t.Errorf("host %q alias[%d] = %q, want %q", host, i, a, firstAliases[i])
				}
			}
		}
	}
}

// TestKnownCloudsAreInternallyConsistent verifies that every alias declared
// in the canonical knownClouds list is reachable through GetKnownMetadata
// and through TrustedHost, that PreferredNetwork is non-empty, and that
// PreferredCache is unique per cloud (ResolveKnownCloud uses it as the
// cloud-identity sentinel, so collisions would silently merge clouds).
func TestKnownCloudsAreInternallyConsistent(t *testing.T) {
	preferredCacheSeen := make(map[string]string)
	for _, cloud := range knownClouds {
		if cloud.PreferredNetwork == "" {
			t.Errorf("cloud %+v has empty PreferredNetwork", cloud)
		}
		if cloud.PreferredCache == "" {
			t.Errorf("cloud %+v has empty PreferredCache", cloud)
		}
		if prev, dup := preferredCacheSeen[cloud.PreferredCache]; dup {
			t.Errorf("PreferredCache %q used by two clouds: %q and %q (must be unique per cloud)",
				cloud.PreferredCache, prev, cloud.PreferredNetwork)
		}
		preferredCacheSeen[cloud.PreferredCache] = cloud.PreferredNetwork
		if len(cloud.Aliases) == 0 {
			t.Errorf("cloud %q has no aliases", cloud.PreferredNetwork)
		}
		for _, alias := range cloud.Aliases {
			md, ok := GetKnownMetadata(alias)
			if !ok {
				t.Errorf("alias %q not reachable through GetKnownMetadata", alias)
				continue
			}
			if md.PreferredNetwork != cloud.PreferredNetwork {
				t.Errorf("alias %q resolves to PreferredNetwork %q, want %q",
					alias, md.PreferredNetwork, cloud.PreferredNetwork)
			}
			if !TrustedHost(alias) {
				t.Errorf("alias %q is not a TrustedHost", alias)
			}
		}
	}
}
