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
			name:    "US Gov sovereign cloud rejected",
			params:  mtlsParams("login.microsoftonline.us", "contoso.onmicrosoft.com", "", ""),
			wantErr: true,
		},
		{
			name:    "US Gov (usgovcloudapi) rejected",
			params:  mtlsParams("login.usgovcloudapi.net", "contoso.onmicrosoft.com", "", ""),
			wantErr: true,
		},
		{
			name:    "China (chinacloudapi) rejected",
			params:  mtlsParams("login.chinacloudapi.cn", "contoso.onmicrosoft.com", "", ""),
			wantErr: true,
		},
		{
			name:    "China (partner.microsoftonline.cn) rejected",
			params:  mtlsParams("login.partner.microsoftonline.cn", "contoso.onmicrosoft.com", "", ""),
			wantErr: true,
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

func TestMtlsPoPSupportedForCloud(t *testing.T) {
	supported := []string{"login.microsoftonline.com", "login.microsoft.com", "login.windows.net", "login.example.com"}
	for _, h := range supported {
		if !mtlsPoPSupportedForCloud(h) {
			t.Errorf("mtlsPoPSupportedForCloud(%q) = false, want true", h)
		}
	}
	unsupported := []string{"login.microsoftonline.us", "login.usgovcloudapi.net", "login.chinacloudapi.cn", "login.partner.microsoftonline.cn"}
	for _, h := range unsupported {
		if mtlsPoPSupportedForCloud(h) {
			t.Errorf("mtlsPoPSupportedForCloud(%q) = true, want false", h)
		}
	}
}
