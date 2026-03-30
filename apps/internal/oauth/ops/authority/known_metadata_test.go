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

// TestTrustedHostsHaveKnownMetadata verifies that every host in the
// aadTrustedHostList has a corresponding entry in GetKnownMetadata. This
// catches maintenance mistakes where a new cloud is added to one list but
// not the other, which would cause fallback to produce a degraded self-entry
// instead of the correct alias set.
func TestTrustedHostsHaveKnownMetadata(t *testing.T) {
	for host := range aadTrustedHostList {
		t.Run(host, func(t *testing.T) {
			md, ok := GetKnownMetadata(host)
			if !ok {
				t.Fatalf("trusted host %q has no entry in GetKnownMetadata", host)
			}
			if md.PreferredNetwork == "" {
				t.Errorf("trusted host %q has empty PreferredNetwork", host)
			}
			if len(md.Aliases) == 0 {
				t.Errorf("trusted host %q has no aliases", host)
			}
		})
	}
}
