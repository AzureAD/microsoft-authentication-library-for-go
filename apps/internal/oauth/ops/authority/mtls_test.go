// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
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
	tests := []struct {
		name    string
		params  AuthParams
		want    string
		wantErr bool
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
			name:   "public cloud, autoDetect region -> global (region optional)",
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
			name:    "organizations authority rejected",
			params:  mtlsParams("login.microsoftonline.com", "organizations", "", ""),
			wantErr: true,
		},
		{
			name:    "consumers authority rejected",
			params:  mtlsParams("login.microsoftonline.com", "consumers", "", ""),
			wantErr: true,
		},
		{
			name:    "non-login host rejected",
			params:  mtlsParams("example.com", "contoso.onmicrosoft.com", "", ""),
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
			got, err := tc.params.MtlsTokenEndpoint()
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
