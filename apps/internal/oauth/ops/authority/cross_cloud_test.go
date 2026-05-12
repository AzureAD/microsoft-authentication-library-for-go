// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"strings"
	"testing"
)

// TestResolveKnownCloud verifies that known Microsoft cloud hosts (and their
// regional sub-hosts) resolve to a non-empty cloud identifier and that
// unknown hosts resolve to "".
func TestResolveKnownCloud(t *testing.T) {
	tests := []struct {
		host     string
		wantNon  bool   // true if a non-empty cloud id is expected
		wantSame string // if non-empty, this host must resolve to the same cloud
	}{
		// Public cloud aliases — all four collapse to the same cloud id.
		{"login.microsoftonline.com", true, "login.windows.net"},
		{"login.windows.net", true, "login.microsoft.com"},
		{"login.microsoft.com", true, "sts.windows.net"},
		{"sts.windows.net", true, "login.microsoftonline.com"},
		// Regional public hosts.
		{"westus2.login.microsoft.com", true, "login.microsoftonline.com"},
		{"eastus2euap.login.microsoft.com", true, "login.windows.net"},
		{"southafricanorth.login.microsoft.com", true, "login.microsoftonline.com"},
		// China.
		{"login.partner.microsoftonline.cn", true, "login.chinacloudapi.cn"},
		{"login.chinacloudapi.cn", true, "login.partner.microsoftonline.cn"},
		{"chinaeast2.login.chinacloudapi.cn", true, "login.partner.microsoftonline.cn"},
		// US Gov.
		{"login.microsoftonline.us", true, "login.usgovcloudapi.net"},
		{"login.usgovcloudapi.net", true, "login.microsoftonline.us"},
		{"usgovvirginia.login.microsoftonline.us", true, "login.microsoftonline.us"},
		// Sovereign clouds.
		{"login.sovcloud-identity.fr", true, ""},
		{"francecentral.login.sovcloud-identity.fr", true, "login.sovcloud-identity.fr"},
		{"login.sovcloud-identity.de", true, ""},
		{"germanywestcentral.login.sovcloud-identity.de", true, "login.sovcloud-identity.de"},
		// Case-insensitive host matching.
		{"LOGIN.MICROSOFTONLINE.COM", true, "login.microsoftonline.com"},
		// Unknown hosts.
		{"", false, ""},
		{"custom.example.com", false, ""},
		{"login.example.com", false, ""},
		// Regional-shape failures over a known base — must NOT resolve.
		{"attacker.evil.login.microsoft.com", false, ""},              // multi-label prefix
		{"weird_prefix.login.microsoft.com", false, ""},               // underscore
		{"-leading.login.microsoft.com", false, ""},                   // leading hyphen
		{"trailing-.login.microsoft.com", false, ""},                  // trailing hyphen
		{strings.Repeat("a", 64) + ".login.microsoft.com", false, ""}, // 64-char prefix
		// Regional-shape over an unknown base — also must not resolve.
		{"westus2.login.example.com", false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			got := ResolveKnownCloud(tc.host)
			if tc.wantNon {
				if got == "" {
					t.Fatalf("ResolveKnownCloud(%q) = %q, want non-empty", tc.host, got)
				}
				if tc.wantSame != "" {
					if other := ResolveKnownCloud(tc.wantSame); other == "" || other != got {
						t.Fatalf("ResolveKnownCloud(%q) = %q, ResolveKnownCloud(%q) = %q; want equal non-empty", tc.host, got, tc.wantSame, other)
					}
				}
			} else if got != "" {
				t.Fatalf("ResolveKnownCloud(%q) = %q, want empty", tc.host, got)
			}
		})
	}
}

// TestAreInSameCloud is the direct unit test for the same-cloud helper.
func TestAreInSameCloud(t *testing.T) {
	pass := []struct{ a, b string }{
		// Public cloud aliases.
		{"login.microsoftonline.com", "login.windows.net"},
		{"login.microsoftonline.com", "westus2.login.microsoft.com"},
		{"login.microsoft.com", "sts.windows.net"},
		// US Gov.
		{"login.microsoftonline.us", "login.usgovcloudapi.net"},
		{"login.microsoftonline.us", "usgovvirginia.login.microsoftonline.us"},
		// China.
		{"login.partner.microsoftonline.cn", "chinaeast2.login.chinacloudapi.cn"},
		{"login.partner.microsoftonline.cn", "login.chinacloudapi.cn"},
		// Bleu (sovereign FR).
		{"login.sovcloud-identity.fr", "francecentral.login.sovcloud-identity.fr"},
		// Case-insensitive.
		{"LOGIN.MICROSOFTONLINE.COM", "login.windows.net"},
	}
	for _, tc := range pass {
		if !AreInSameCloud(tc.a, tc.b) {
			t.Errorf("AreInSameCloud(%q, %q) = false, want true", tc.a, tc.b)
		}
		if !AreInSameCloud(tc.b, tc.a) {
			t.Errorf("AreInSameCloud(%q, %q) = false, want true (commutativity)", tc.b, tc.a)
		}
	}

	reject := []struct{ a, b string }{
		// Different known clouds.
		{"login.microsoftonline.com", "login.partner.microsoftonline.cn"},
		{"login.microsoftonline.com", "login.microsoftonline.us"},
		{"login.microsoftonline.us", "login.chinacloudapi.cn"},
		{"login.microsoftonline.com", "login.microsoftonline.de"},
		{"login.sovcloud-identity.fr", "login.sovcloud-identity.de"},
		// Unknown vs known.
		{"login.microsoftonline.com", "custom.example.com"},
		{"custom.example.com", "another.example.org"},
		// Empty/null inputs.
		{"custom.example.com", ""},
		{"", "login.microsoftonline.com"},
		{"", ""},
		// Regional-shape failures over a known base.
		{"attacker.evil.login.microsoft.com", "login.microsoftonline.com"},
		{"weird_prefix.login.microsoft.com", "login.microsoftonline.com"},
		{"-leading.login.microsoft.com", "login.microsoftonline.com"},
		{"trailing-.login.microsoft.com", "login.microsoftonline.com"},
		{strings.Repeat("a", 64) + ".login.microsoft.com", "login.microsoftonline.com"},
	}
	for _, tc := range reject {
		if AreInSameCloud(tc.a, tc.b) {
			t.Errorf("AreInSameCloud(%q, %q) = true, want false", tc.a, tc.b)
		}
	}
}

// TestValidateIssuer_CrossCloudRejected exercises the cross-cloud combinations
// that were silently accepted before the fix and must now throw.
func TestValidateIssuer_CrossCloudRejected(t *testing.T) {
	tests := []struct {
		desc      string
		authority string
		issuer    string
	}{
		{"public authority + China issuer",
			"https://login.microsoftonline.com/tenant",
			"https://login.partner.microsoftonline.cn/tenant"},
		{"public authority + US Gov issuer",
			"https://login.microsoftonline.com/tenant",
			"https://login.microsoftonline.us/tenant"},
		{"US Gov authority + Public issuer",
			"https://login.microsoftonline.us/tenant",
			"https://login.microsoftonline.com/tenant"},
		{"China authority + Public issuer",
			"https://login.partner.microsoftonline.cn/tenant",
			"https://login.microsoftonline.com/tenant"},
		{"public authority + regional China issuer",
			"https://login.microsoftonline.com/tenant",
			"https://chinaeast2.login.chinacloudapi.cn/tenant"},
		{"US Gov authority + regional Public issuer",
			"https://login.microsoftonline.us/tenant",
			"https://westus2.login.microsoft.com/tenant"},
		{"Bleu authority + Delos issuer",
			"https://login.sovcloud-identity.fr/tenant",
			"https://login.sovcloud-identity.de/tenant"},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			r := &TenantDiscoveryResponse{
				AuthorizationEndpoint: tc.authority + "/oauth2/v2.0/authorize",
				TokenEndpoint:         tc.authority + "/oauth2/v2.0/token",
				Issuer:                tc.issuer,
			}
			if err := r.ValidateIssuerMatchesAuthority(tc.authority, nil); err == nil {
				t.Fatalf("expected cross-cloud rejection but got nil for authority=%q issuer=%q", tc.authority, tc.issuer)
			}
		})
	}
}

// TestValidateIssuer_SameCloudAccepted verifies the every-cloud × every-alias
// matrix from category B of the spec.
func TestValidateIssuer_SameCloudAccepted(t *testing.T) {
	tests := []struct {
		desc      string
		authority string
		issuer    string
	}{
		// Public cloud cross-alias acceptance.
		{"public ↔ login.windows.net",
			"https://login.microsoftonline.com/tenant",
			"https://login.windows.net/tenant"},
		{"public ↔ sts.windows.net",
			"https://login.microsoftonline.com/tenant",
			"https://sts.windows.net/tenant"},
		{"public ↔ login.microsoft.com",
			"https://login.microsoftonline.com/tenant",
			"https://login.microsoft.com/tenant"},
		{"US Gov ↔ login.usgovcloudapi.net",
			"https://login.microsoftonline.us/tenant",
			"https://login.usgovcloudapi.net/tenant"},
		{"China ↔ login.chinacloudapi.cn",
			"https://login.partner.microsoftonline.cn/tenant",
			"https://login.chinacloudapi.cn/tenant"},
		// Regional same-cloud.
		{"public ↔ regional public",
			"https://login.microsoftonline.com/tenant",
			"https://westus2.login.microsoft.com/tenant"},
		{"China ↔ regional China",
			"https://login.partner.microsoftonline.cn/tenant",
			"https://chinaeast2.login.chinacloudapi.cn/tenant"},
		{"Delos ↔ regional Delos",
			"https://login.sovcloud-identity.de/tenant",
			"https://germanywestcentral.login.sovcloud-identity.de/tenant"},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			r := &TenantDiscoveryResponse{
				AuthorizationEndpoint: tc.authority + "/oauth2/v2.0/authorize",
				TokenEndpoint:         tc.authority + "/oauth2/v2.0/token",
				Issuer:                tc.issuer,
			}
			if err := r.ValidateIssuerMatchesAuthority(tc.authority, nil); err != nil {
				t.Fatalf("expected acceptance but got err=%v for authority=%q issuer=%q", err, tc.authority, tc.issuer)
			}
		})
	}
}

// TestValidateIssuer_CustomDomainFederation covers Rule 2a: a custom-domain
// authority is allowed to federate with any known Microsoft cloud issuer.
// This is the regression path for issue
// AzureAD/microsoft-authentication-library-for-dotnet#5927.
func TestValidateIssuer_CustomDomainFederation(t *testing.T) {
	tests := []struct {
		desc      string
		authority string
		issuer    string
	}{
		{"parentpay-style federation with public",
			"https://clientlogin.test.parentpay.com/tid/v2.0",
			"https://login.microsoftonline.com/tid/v2.0"},
		{"custom domain federation with US Gov",
			"https://customlogin.example.com/tenant",
			"https://login.microsoftonline.us/tenant"},
		{"custom domain federation with China",
			"https://idp.contoso.com/tenant",
			"https://login.partner.microsoftonline.cn/tenant"},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			r := &TenantDiscoveryResponse{
				AuthorizationEndpoint: tc.authority + "/oauth2/v2.0/authorize",
				TokenEndpoint:         tc.authority + "/oauth2/v2.0/token",
				Issuer:                tc.issuer,
			}
			if err := r.ValidateIssuerMatchesAuthority(tc.authority, nil); err != nil {
				t.Fatalf("expected #5927-style acceptance but got err=%v", err)
			}
		})
	}
}

// TestValidateIssuer_CIAM exercises Rule 4 (CIAM tenant pattern).
func TestValidateIssuer_CIAM(t *testing.T) {
	pass := []struct {
		desc      string
		authority string
		issuer    string
	}{
		{"CIAM via custom domain authority",
			"https://customdomain.com/contoso",
			"https://contoso.ciamlogin.com/contoso/v2.0"},
		{"CIAM with bare host issuer",
			"https://contoso.ciamlogin.com",
			"https://contoso.ciamlogin.com"},
		{"CIAM with tenant-only path",
			"https://customdomain.com/contoso",
			"https://contoso.ciamlogin.com/contoso"},
		{"CIAM with bare host (no path)",
			"https://customdomain.com/contoso",
			"https://contoso.ciamlogin.com"},
	}
	for _, tc := range pass {
		t.Run(tc.desc, func(t *testing.T) {
			r := &TenantDiscoveryResponse{
				AuthorizationEndpoint: tc.authority + "/oauth2/v2.0/authorize",
				TokenEndpoint:         tc.authority + "/oauth2/v2.0/token",
				Issuer:                tc.issuer,
			}
			if err := r.ValidateIssuerMatchesAuthority(tc.authority, nil); err != nil {
				t.Fatalf("expected CIAM acceptance, got err=%v", err)
			}
		})
	}

	throw := []struct {
		desc      string
		authority string
		issuer    string
	}{
		{"CIAM tenant mismatch",
			"https://customdomain.com/tenantA",
			"https://tenantB.ciamlogin.com/tenantB/v2.0"},
		{"CIAM with wrong issuer path tenant",
			"https://customdomain.com/contoso",
			"https://contoso.ciamlogin.com/wrongtenant/v2.0"},
	}
	for _, tc := range throw {
		t.Run(tc.desc, func(t *testing.T) {
			r := &TenantDiscoveryResponse{
				AuthorizationEndpoint: tc.authority + "/oauth2/v2.0/authorize",
				TokenEndpoint:         tc.authority + "/oauth2/v2.0/token",
				Issuer:                tc.issuer,
			}
			if err := r.ValidateIssuerMatchesAuthority(tc.authority, nil); err == nil {
				t.Fatalf("expected rejection for CIAM tenant mismatch but got nil")
			}
		})
	}
}

// TestValidateIssuer_OtherRejections covers category G of the spec: other
// rejections that must throw both before AND after the fix.
func TestValidateIssuer_OtherRejections(t *testing.T) {
	tests := []struct {
		desc      string
		authority string
		issuer    string
	}{
		{"http issuer scheme under known-MS authority",
			"https://login.microsoftonline.com/tenant",
			"http://login.microsoftonline.com/tenant"},
		{"custom authority + unknown-host issuer",
			"https://customlogin.example.com/tenant",
			"https://otherhost.example.com/tenant"},
		{"custom authority + spoofed-but-not-known host",
			"https://customlogin.example.com/tenant",
			"https://fake-login.microsoftonline.com/tenant"},
		{"regional-shaped prefix on unknown base",
			"https://login.microsoftonline.com/tenant",
			"https://westus2.login.example.com/tenant"},
		{"empty issuer",
			"https://login.microsoftonline.com/tenant",
			""},
		{"multi-label prefix on known base",
			"https://login.microsoftonline.com/tenant",
			"https://attacker.evil.login.microsoft.com/tenant"},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			r := &TenantDiscoveryResponse{
				AuthorizationEndpoint: tc.authority + "/oauth2/v2.0/authorize",
				TokenEndpoint:         tc.authority + "/oauth2/v2.0/token",
				Issuer:                tc.issuer,
			}
			if err := r.ValidateIssuerMatchesAuthority(tc.authority, nil); err == nil {
				t.Fatalf("expected rejection but got nil for %s", tc.desc)
			}
		})
	}
}

// TestValidateIssuer_BehaviorMatrix is the single-source-of-truth table
// described in category J. It documents BEFORE vs AFTER for every meaningful
// (authority shape, issuer shape) combination, so a future regression is
// visible at a glance.
func TestValidateIssuer_BehaviorMatrix(t *testing.T) {
	type row struct {
		desc   string
		auth   string
		iss    string
		before bool // accepted by the old code
		after  bool // accepted by the new code
	}
	matrix := []row{
		// --- Pass before AND after (no behavior change) -----------------------
		{"Rule 1 exact host", "https://login.microsoftonline.com/t", "https://login.microsoftonline.com/t/v2.0", true, true},
		{"Rule 2 same-cloud (public alias)", "https://login.microsoftonline.com/t", "https://login.windows.net/t", true, true},
		{"Rule 2 same-cloud (regional public)", "https://login.microsoftonline.com/t", "https://westus2.login.microsoft.com/t", true, true},
		{"Rule 2 same-cloud (US Gov alias)", "https://login.microsoftonline.us/t", "https://login.usgovcloudapi.net/t", true, true},
		{"#5927 federation parentpay style", "https://clientlogin.test.parentpay.com/tid/v2.0", "https://login.microsoftonline.com/tid/v2.0", true, true},

		// --- Passed before, NOW THROWS (the fix) ------------------------------
		{"cross-cloud public ↔ China", "https://login.microsoftonline.com/t", "https://login.partner.microsoftonline.cn/t", true, false},
		{"cross-cloud public ↔ US Gov", "https://login.microsoftonline.com/t", "https://login.microsoftonline.us/t", true, false},
		{"cross-cloud US Gov ↔ Public", "https://login.microsoftonline.us/t", "https://login.microsoftonline.com/t", true, false},
		{"cross-cloud China ↔ Public", "https://login.partner.microsoftonline.cn/t", "https://login.microsoftonline.com/t", true, false},
		{"cross-cloud public ↔ regional China", "https://login.microsoftonline.com/t", "https://chinaeast2.login.chinacloudapi.cn/t", true, false},
		{"cross-cloud US Gov ↔ regional Public", "https://login.microsoftonline.us/t", "https://westus2.login.microsoft.com/t", true, false},
		{"cross-cloud Bleu ↔ Delos", "https://login.sovcloud-identity.fr/t", "https://login.sovcloud-identity.de/t", true, false},

		// --- Throws before AND after (no change) ------------------------------
		{"http scheme under known-MS authority", "https://login.microsoftonline.com/t", "http://login.microsoftonline.com/t", false, false},
		{"unknown issuer + custom authority", "https://customlogin.example.com/t", "https://otherhost.example.com/t", false, false},
		{"multi-label regional-looking", "https://login.microsoftonline.com/t", "https://attacker.evil.login.microsoft.com/t", false, false},

		// --- Threw before, NOW PASSES (only #5927-style federation) -----------
		// (Already covered above by the parentpay row, kept here for completeness
		// with an additional cross-cloud federation case.)
		// Old code accepted this via the TrustedHost(issuerHost) fallback, so
		// 'before' is true. The new code accepts it via Rule 2a explicitly.
		{"#5927 federation US Gov", "https://customlogin.example.com/t", "https://login.microsoftonline.us/t", true, true},
	}

	for _, r := range matrix {
		t.Run(r.desc, func(t *testing.T) {
			resp := &TenantDiscoveryResponse{
				AuthorizationEndpoint: r.auth + "/oauth2/v2.0/authorize",
				TokenEndpoint:         r.auth + "/oauth2/v2.0/token",
				Issuer:                r.iss,
			}
			err := resp.ValidateIssuerMatchesAuthority(r.auth, nil)
			accepted := err == nil
			if accepted != r.after {
				t.Fatalf("matrix row %q: accepted=%v, want %v (after); err=%v", r.desc, accepted, r.after, err)
			}
		})
	}
}
