// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mtls-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing cert: %v", err)
	}
	return cert
}

func TestMtlsPoPAuthenticationScheme(t *testing.T) {
	cert := testCert(t)
	scheme := NewMtlsPoPAuthenticationScheme(cert)

	params := scheme.TokenRequestParams()
	if got := params["token_type"]; got != AccessTokenTypeMtlsPoP {
		t.Errorf("token_type = %q, want %q", got, AccessTokenTypeMtlsPoP)
	}
	// The binding is performed by the TLS client certificate, so there must be no req_cnf.
	if _, ok := params["req_cnf"]; ok {
		t.Error("TokenRequestParams unexpectedly set req_cnf; mTLS PoP must not send req_cnf")
	}
	if len(params) != 1 {
		t.Errorf("TokenRequestParams returned %d params, want exactly 1 (token_type)", len(params))
	}

	sum := sha256.Sum256(cert.Raw)
	wantKeyID := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := scheme.KeyID(); got != wantKeyID {
		t.Errorf("KeyID = %q, want %q (x5t#S256)", got, wantKeyID)
	}

	if got := scheme.AccessTokenType(); got != AccessTokenTypeMtlsPoP {
		t.Errorf("AccessTokenType = %q, want %q", got, AccessTokenTypeMtlsPoP)
	}

	const at = "eyJhbGciOi.some.token"
	formatted, err := scheme.FormatAccessToken(at)
	if err != nil {
		t.Fatalf("FormatAccessToken returned error: %v", err)
	}
	if formatted != at {
		t.Errorf("FormatAccessToken changed the token: got %q, want %q", formatted, at)
	}
}

func mtlsParams(host, tenant, region, tokenEndpoint string) AuthParams {
	return AuthParams{
		AuthorityInfo: Info{Host: host, Tenant: tenant, Region: region},
		Endpoints:     Endpoints{TokenEndpoint: tokenEndpoint},
	}
}

func TestMtlsTokenEndpoint(t *testing.T) {
	// Auto-detection reads REGION_NAME before probing IMDS, which lets the auto-detect case below
	// exercise the real resolution path without a network call.
	const detectedRegion = "centralus"
	if err := os.Setenv(regionName, detectedRegion); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv(regionName)

	tests := []struct {
		name string
		// resolveRegion runs Info.ResolveRegion first, exactly as the token path does before
		// deriving the endpoint.
		resolveRegion bool
		params        AuthParams
		want          string
		wantErr       bool
	}{
		{
			name:   "public cloud, no region -> global mtlsauth.microsoft.com",
			params: mtlsParams("login.microsoftonline.com", "contoso.onmicrosoft.com", "", "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://mtlsauth.microsoft.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "public cloud, concrete region -> region.mtlsauth.microsoft.com",
			params: mtlsParams("login.microsoftonline.com", "contoso.onmicrosoft.com", "westus", "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://westus.mtlsauth.microsoft.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			// A successfully auto-detected region must reach the endpoint. This used to yield the
			// global host because the sentinel was never replaced with the detected value.
			name:          "public cloud, autoDetect region resolves to the detected region",
			resolveRegion: true,
			params:        mtlsParams("login.microsoftonline.com", "contoso.onmicrosoft.com", autoDetectRegion, "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:          "https://" + detectedRegion + ".mtlsauth.microsoft.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			// Detection that finds nothing leaves the region empty, and the global endpoint is the
			// documented, production-ready fallback.
			name:   "public cloud, unresolved autoDetect sentinel -> global",
			params: mtlsParams("login.microsoftonline.com", "contoso.onmicrosoft.com", autoDetectRegion, "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://mtlsauth.microsoft.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "login.microsoft.com public alias -> global mtlsauth.microsoft.com",
			params: mtlsParams("login.microsoft.com", "contoso.onmicrosoft.com", "", "https://login.microsoft.com/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://mtlsauth.microsoft.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "non-public login host -> literal login->mtlsauth swap",
			params: mtlsParams("login.example.com", "contoso.onmicrosoft.com", "", "https://login.example.com/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://mtlsauth.example.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "non-public login host with region",
			params: mtlsParams("login.example.com", "contoso.onmicrosoft.com", "eastus", "https://login.example.com/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://eastus.mtlsauth.example.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			// Info.Host comes from url.URL.Host, which keeps an explicit port. Without splitting it
			// off, the known-host lookup misses and the fallback swap yields
			// mtlsauth.microsoftonline.com:443 instead of the normalized public host.
			name:   "public cloud host with explicit port -> normalized host, port preserved",
			params: mtlsParams("login.microsoftonline.com:443", "contoso.onmicrosoft.com", "", "https://login.microsoftonline.com:443/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://mtlsauth.microsoft.com:443/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "public cloud host with explicit port and region",
			params: mtlsParams("login.microsoftonline.com:8443", "contoso.onmicrosoft.com", "westus", "https://login.microsoftonline.com:8443/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://westus.mtlsauth.microsoft.com:8443/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "sovereign alias with explicit port normalizes then keeps the port",
			params: mtlsParams("login.usgovcloudapi.net:443", "contoso.onmicrosoft.com", "", "https://login.usgovcloudapi.net:443/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://mtlsauth.microsoftonline.us:443/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "private cloud login host with port",
			params: mtlsParams("login.contoso.internal:9443", "contoso.onmicrosoft.com", "", ""),
			want:   "https://mtlsauth.contoso.internal:9443/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "no resolved token endpoint -> synthesized path",
			params: mtlsParams("login.microsoftonline.com", "mytenant", "", ""),
			want:   "https://mtlsauth.microsoft.com/mytenant/oauth2/v2.0/token",
		},
		{
			name:    "empty tenant rejected",
			params:  mtlsParams("login.microsoftonline.com", "", "", ""),
			wantErr: true,
		},
		{
			name:    "common authority rejected",
			params:  mtlsParams("login.microsoftonline.com", "common", "", ""),
			wantErr: true,
		},
		{
			// The tenant is compared case-insensitively so the guard stands on its own rather than
			// relying on the authority URL having been lowercased at parse time.
			name:    "COMMON authority rejected regardless of case",
			params:  mtlsParams("login.microsoftonline.com", "COMMON", "", ""),
			wantErr: true,
		},
		{
			name:    "organizations authority rejected",
			params:  mtlsParams("login.microsoftonline.com", "organizations", "", ""),
			wantErr: true,
		},
		{
			name:    "Organizations authority rejected regardless of case",
			params:  mtlsParams("login.microsoftonline.com", "Organizations", "", ""),
			wantErr: true,
		},
		{
			name:    "consumers authority rejected",
			params:  mtlsParams("login.microsoftonline.com", "consumers", "", ""),
			wantErr: true,
		},
		{
			name:    "CONSUMERS authority rejected regardless of case",
			params:  mtlsParams("login.microsoftonline.com", "CONSUMERS", "", ""),
			wantErr: true,
		},
		{
			name:    "non-login host rejected",
			params:  mtlsParams("example.com", "contoso.onmicrosoft.com", "", ""),
			wantErr: true,
		},
		{
			// sts.windows.net is a public-cloud alias but has no login. prefix, so it is rejected
			// by the host guard. MSAL .NET rejects it the same way.
			name:    "sts.windows.net rejected",
			params:  mtlsParams("sts.windows.net", "contoso.onmicrosoft.com", "", ""),
			wantErr: true,
		},
		{
			name:   "US Gov (login.microsoftonline.us) -> mtlsauth.microsoftonline.us",
			params: mtlsParams("login.microsoftonline.us", "contoso.onmicrosoft.com", "", "https://login.microsoftonline.us/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://mtlsauth.microsoftonline.us/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "US Gov with region -> regional mtlsauth.microsoftonline.us",
			params: mtlsParams("login.microsoftonline.us", "contoso.onmicrosoft.com", "usgovvirginia", "https://login.microsoftonline.us/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://usgovvirginia.mtlsauth.microsoftonline.us/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "China (login.partner.microsoftonline.cn) -> mtlsauth.partner.microsoftonline.cn",
			params: mtlsParams("login.partner.microsoftonline.cn", "contoso.onmicrosoft.com", "", "https://login.partner.microsoftonline.cn/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://mtlsauth.partner.microsoftonline.cn/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "US Gov legacy host (login.usgovcloudapi.net) -> mtlsauth.microsoftonline.us",
			params: mtlsParams("login.usgovcloudapi.net", "contoso.onmicrosoft.com", "", "https://login.usgovcloudapi.net/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://mtlsauth.microsoftonline.us/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "US Gov legacy host with region -> regional mtlsauth.microsoftonline.us",
			params: mtlsParams("login.usgovcloudapi.net", "contoso.onmicrosoft.com", "usgovvirginia", "https://login.usgovcloudapi.net/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://usgovvirginia.mtlsauth.microsoftonline.us/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "China legacy host (login.chinacloudapi.cn) -> mtlsauth.partner.microsoftonline.cn",
			params: mtlsParams("login.chinacloudapi.cn", "contoso.onmicrosoft.com", "", "https://login.chinacloudapi.cn/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://mtlsauth.partner.microsoftonline.cn/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "China legacy host with region -> regional mtlsauth.partner.microsoftonline.cn",
			params: mtlsParams("login.chinacloudapi.cn", "contoso.onmicrosoft.com", "chinanorth3", "https://login.chinacloudapi.cn/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://chinanorth3.mtlsauth.partner.microsoftonline.cn/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "China modern host with region -> regional mtlsauth.partner.microsoftonline.cn",
			params: mtlsParams("login.partner.microsoftonline.cn", "contoso.onmicrosoft.com", "chinanorth3", "https://login.partner.microsoftonline.cn/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://chinanorth3.mtlsauth.partner.microsoftonline.cn/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "Germany legacy cloud (its preferred network is itself) -> mtlsauth.microsoftonline.de",
			params: mtlsParams("login.microsoftonline.de", "contoso.onmicrosoft.com", "", "https://login.microsoftonline.de/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://mtlsauth.microsoftonline.de/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "Germany legacy cloud with region",
			params: mtlsParams("login.microsoftonline.de", "contoso.onmicrosoft.com", "germanywestcentral", "https://login.microsoftonline.de/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://germanywestcentral.mtlsauth.microsoftonline.de/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params := tc.params
			if tc.resolveRegion {
				params.AuthorityInfo.ResolveRegion(context.Background())
			}
			got, err := params.MtlsTokenEndpoint()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("MtlsTokenEndpoint() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("MtlsTokenEndpoint() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("MtlsTokenEndpoint() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMtlsTokenEndpointRejectsNonAADAuthorities documents that ADFS and dSTS are out of scope for
// mTLS proof-of-possession, and pins that the rejection is clear and actionable rather than a
// confusing network failure. MSAL .NET is the same: dSTS never reaches its dedicated rejection
// message (that message has no call sites), it is refused by the login.-prefix host check.
func TestMtlsTokenEndpointRejectsNonAADAuthorities(t *testing.T) {
	for _, test := range []struct {
		desc      string
		authority string
	}{
		{desc: "dSTS", authority: "https://dsts.core.windows.net/dstsv2/" + DSTSTenant},
		{desc: "ADFS", authority: "https://fs.contoso.com/adfs"},
	} {
		t.Run(test.desc, func(t *testing.T) {
			info, err := NewInfoFromAuthorityURI(test.authority, true, false)
			if err != nil {
				t.Fatalf("NewInfoFromAuthorityURI(%q): %v", test.authority, err)
			}
			params := AuthParams{AuthorityInfo: info}
			got, err := params.MtlsTokenEndpoint()
			if err == nil {
				t.Fatalf("MtlsTokenEndpoint() = %q, want an error for a %s authority", got, test.desc)
			}
			// The message has to name the offending host and say what is required, otherwise the
			// caller has no way to tell why an ordinary-looking authority was refused.
			msg := err.Error()
			if !strings.Contains(msg, info.Host) {
				t.Errorf("error %q does not name the authority host %q", msg, info.Host)
			}
			if !strings.Contains(msg, "mTLS proof-of-possession") || !strings.Contains(msg, "login.") {
				t.Errorf("error %q does not explain that mTLS proof-of-possession requires a login.* host", msg)
			}
		})
	}
}

// TestSplitHostPort covers the host/port split used before the known-host lookup, including the
// bare-hostname and IPv6-literal shapes that must not be mangled.
func TestSplitHostPort(t *testing.T) {
	for _, test := range []struct {
		in       string
		wantHost string
		wantPort string
	}{
		{in: "login.microsoftonline.com", wantHost: "login.microsoftonline.com"},
		{in: "login.microsoftonline.com:443", wantHost: "login.microsoftonline.com", wantPort: "443"},
		{in: "[::1]", wantHost: "[::1]"},
		{in: "[::1]:8443", wantHost: "[::1]", wantPort: "8443"},
		{in: "", wantHost: ""},
	} {
		host, port := splitHostPort(test.in)
		if host != test.wantHost || port != test.wantPort {
			t.Errorf("splitHostPort(%q) = (%q, %q), want (%q, %q)", test.in, host, port, test.wantHost, test.wantPort)
		}
	}
}

func TestMtlsPoPSovereignAliasesMatchPreferredNetwork(t *testing.T) {
	// Legacy sovereign hostnames are aliases, not separate clouds: each must derive the same mTLS
	// endpoint as the modern hostname it normalizes to, rather than a literal login -> mtlsauth swap
	// of the alias itself (which would yield a host that is never served, e.g.
	// mtlsauth.usgovcloudapi.net). This mirrors MSAL.NET, which resolves the preferred-network host
	// before rewriting.
	aliases := map[string]string{
		"login.usgovcloudapi.net": "login.microsoftonline.us",
		"login.chinacloudapi.cn":  "login.partner.microsoftonline.cn",
	}
	for alias, modern := range aliases {
		for _, region := range []string{"", "eastus"} {
			name := alias
			if region != "" {
				name += "/" + region
			}
			t.Run(name, func(t *testing.T) {
				aliasEndpoint, err := mtlsParams(alias, "contoso.onmicrosoft.com", region, "").MtlsTokenEndpoint()
				if err != nil {
					t.Fatalf("alias host %q: unexpected error: %v", alias, err)
				}
				modernEndpoint, err := mtlsParams(modern, "contoso.onmicrosoft.com", region, "").MtlsTokenEndpoint()
				if err != nil {
					t.Fatalf("modern host %q: unexpected error: %v", modern, err)
				}
				if aliasEndpoint != modernEndpoint {
					t.Errorf("alias %q derived %q, want the same endpoint as %q (%q)", alias, aliasEndpoint, modern, modernEndpoint)
				}
				if strings.Contains(aliasEndpoint, "usgovcloudapi") || strings.Contains(aliasEndpoint, "chinacloudapi") {
					t.Errorf("alias %q derived %q, which keeps the alias hostname instead of its preferred network", alias, aliasEndpoint)
				}
			})
		}
	}
}

// TestMtlsPoPKnownSovereignHostsSupported guards against a regression to the old behavior, where a
// hardcoded block list rejected sovereign hosts outright.
func TestMtlsPoPKnownSovereignHostsSupported(t *testing.T) {
	for _, host := range []string{
		"login.microsoftonline.com", "login.microsoft.com", "login.windows.net", "login.example.com",
		"login.microsoftonline.us", "login.partner.microsoftonline.cn",
		"login.usgovcloudapi.net", "login.chinacloudapi.cn", "login.microsoftonline.de",
	} {
		t.Run(host, func(t *testing.T) {
			got, err := mtlsParams(host, "contoso.onmicrosoft.com", "", "").MtlsTokenEndpoint()
			if err != nil {
				t.Fatalf("host %q must be supported for mTLS PoP, got error: %v", host, err)
			}
			if !strings.Contains(got, "//"+mtlsAuthPrefix+".") {
				t.Errorf("host %q derived %q, want an mtlsauth.* host", host, got)
			}
		})
	}
}
