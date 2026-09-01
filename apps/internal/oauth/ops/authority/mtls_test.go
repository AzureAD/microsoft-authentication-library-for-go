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
	"net/url"
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

// mtlsParams builds params for an ordinary AAD authority on a trusted host. AuthorityType is set
// explicitly because ValidateMtlsPoP requires it and a zero Info is not an AAD authority.
func mtlsParams(host, tenant, region, tokenEndpoint string) AuthParams {
	return AuthParams{
		AuthorityInfo: Info{Host: host, Tenant: tenant, Region: region, AuthorityType: AAD},
		Endpoints:     Endpoints{TokenEndpoint: tokenEndpoint},
	}
}

// mtlsPrivateCloudParams is mtlsParams plus the explicit private-cloud trust decision a caller makes
// with WithInstanceDiscovery(false). A login.* host outside the known clouds needs it before its
// mtlsauth.* endpoint may be derived; see ValidateMtlsPoP.
func mtlsPrivateCloudParams(host, tenant, region, tokenEndpoint string) AuthParams {
	p := mtlsParams(host, tenant, region, tokenEndpoint)
	p.AuthorityInfo.InstanceDiscoveryDisabled = true
	return p
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
			params: mtlsPrivateCloudParams("login.example.com", "contoso.onmicrosoft.com", "", "https://login.example.com/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://mtlsauth.example.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:   "non-public login host with region",
			params: mtlsPrivateCloudParams("login.example.com", "contoso.onmicrosoft.com", "eastus", "https://login.example.com/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			want:   "https://eastus.mtlsauth.example.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			// An untrusted login.* host with no private-cloud opt-in must not be rewritten: the
			// derived host receives the binding certificate and the client assertion.
			name:    "non-public login host without the private-cloud opt-in rejected",
			params:  mtlsParams("login.example.com", "contoso.onmicrosoft.com", "", "https://login.example.com/contoso.onmicrosoft.com/oauth2/v2.0/token"),
			wantErr: true,
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
			params: mtlsPrivateCloudParams("login.contoso.internal:9443", "contoso.onmicrosoft.com", "", ""),
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

// TestMtlsTokenEndpointRejectsADFSByAuthorityType pins that mTLS PoP refuses an ADFS authority
// because of its AuthorityType, not because of its host.
//
// Its predecessor used https://fs.contoso.com/adfs, which is not login.*-hosted, so the host check
// refused it and the test passed identically with no type check at all. AuthorityType is decided by
// the authority's first path segment and never by its host (see NewInfoFromAuthorityURI), so a
// non-AAD authority can be login.*-hosted: https://login.microsoftonline.com/adfs derived an
// mtlsauth.* endpoint before this guard existed.
//
// The case holds the host and the tenant fixed and varies exactly one thing, the authority type, by
// running the same parsed Info twice with only AuthorityType changed. The control must be accepted,
// which proves every other guard passes for these params, so the rejection can only be the type
// check; the message assertions prove which guard fired.
//
// dSTS is deliberately absent: it is supported, and TestMtlsTokenEndpointAcceptsTenantedDSTS covers
// it.
func TestMtlsTokenEndpointRejectsADFSByAuthorityType(t *testing.T) {
	const authority = "https://login.microsoftonline.com/adfs"
	const wantEndpoint = "https://mtlsauth.microsoft.com/adfs/oauth2/v2.0/token"

	info, err := NewInfoFromAuthorityURI(authority, true, false)
	if err != nil {
		t.Fatalf("NewInfoFromAuthorityURI(%q): %v", authority, err)
	}
	if info.AuthorityType != ADFS {
		t.Fatalf("AuthorityType = %q, want %q; this test no longer tests what it claims to", info.AuthorityType, ADFS)
	}

	// The control runs first. With AuthorityType relabelled AAD and nothing else touched, the
	// authority is accepted, so no other guard can explain the rejection below.
	control := info
	control.AuthorityType = AAD
	got, err := (AuthParams{AuthorityInfo: control}).MtlsTokenEndpoint()
	if err != nil {
		t.Fatalf("the control (identical Info, AuthorityType=%s) was rejected: %v; this test can no longer isolate the authority type", AAD, err)
	}
	if got != wantEndpoint {
		t.Fatalf("the control derived %q, want %q", got, wantEndpoint)
	}

	got, err = (AuthParams{AuthorityInfo: info}).MtlsTokenEndpoint()
	if err == nil {
		t.Fatalf("MtlsTokenEndpoint() = %q, want an %s authority to be rejected", got, ADFS)
	}
	msg := err.Error()
	if !strings.Contains(msg, ADFS) {
		t.Errorf("error %q does not name the offending authority type %q", msg, ADFS)
	}
	if strings.Contains(msg, "a login.* host is required") || strings.Contains(msg, "tenanted authority") {
		t.Errorf("error %q came from the host or tenant guard, not the authority-type guard", msg)
	}

	// An ADFS authority that is not login.*-hosted stays rejected too. It has no control, because
	// relabelling it AAD leaves it refused by the host guard.
	t.Run("ADFS on its own host", func(t *testing.T) {
		info, err := NewInfoFromAuthorityURI("https://fs.contoso.com/adfs", true, false)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := (AuthParams{AuthorityInfo: info}).MtlsTokenEndpoint(); err == nil {
			t.Fatalf("MtlsTokenEndpoint() = %q, want an ADFS authority to be rejected", got)
		}
	})
}

// TestMtlsTokenEndpointAcceptsTenantedDSTS pins that a tenanted dSTS authority is supported for mTLS
// PoP and keeps its own resolved token endpoint rather than being rewritten to mtlsauth.*.
//
// MSAL .NET supports it: ValidateAadAuthorityForPop returns early for any non-AAD authority instead
// of rejecting it, and the login. -> mtlsauth rewrite in RegionAndMtlsDiscoveryProvider is
// conditional on a login.-prefixed host, which a real dSTS authority is not.
//
// The "keeps its own host" assertions are the security-relevant half. dSTS is exempt from the
// login.* and trusted-host guards precisely because nothing is derived from its host; if a rewrite
// were ever introduced, that exemption would start handing the binding certificate to a derived host
// that no allowlist covers. These assertions fail if that happens.
func TestMtlsTokenEndpointAcceptsTenantedDSTS(t *testing.T) {
	for _, test := range []struct {
		desc          string
		authority     string
		tokenEndpoint string
		region        string
		want          string
	}{
		{
			desc:          "dSTS on its own host",
			authority:     "https://dsts.core.windows.net/dstsv2/" + DSTSTenant,
			tokenEndpoint: "https://dsts.core.windows.net/dstsv2/" + DSTSTenant + "/oauth2/v2.0/token",
			want:          "https://dsts.core.windows.net/dstsv2/" + DSTSTenant + "/oauth2/v2.0/token",
		},
		{
			// Region is an AAD concept: RegionAndMtlsDiscoveryProvider builds <region>.<host> only
			// on the AAD path. Configuring one must not regionalize a dSTS endpoint, because the
			// resulting host would not exist and the failure would surface as a DNS or TLS error
			// far from its cause.
			desc:          "a configured region does not alter the dSTS endpoint",
			authority:     "https://dsts.core.windows.net/dstsv2/" + DSTSTenant,
			tokenEndpoint: "https://dsts.core.windows.net/dstsv2/" + DSTSTenant + "/oauth2/v2.0/token",
			region:        "westus",
			want:          "https://dsts.core.windows.net/dstsv2/" + DSTSTenant + "/oauth2/v2.0/token",
		},
		{
			// A login.*-hosted dSTS authority is still not rewritten. The rewrite is scoped to the
			// authority type, not to the host shape, so this cannot become mtlsauth.microsoft.com.
			desc:          "dSTS on the public cloud login host is still not rewritten",
			authority:     "https://login.microsoftonline.com/dstsv2/" + DSTSTenant,
			tokenEndpoint: "https://login.microsoftonline.com/dstsv2/" + DSTSTenant + "/oauth2/v2.0/token",
			want:          "https://login.microsoftonline.com/dstsv2/" + DSTSTenant + "/oauth2/v2.0/token",
		},
		{
			// An untrusted host is accepted for dSTS because no host is derived from it. This is
			// the exemption from the trusted-host guard, stated as a test.
			desc:          "dSTS on an untrusted host",
			authority:     "https://dsts.contoso.example/dstsv2/" + DSTSTenant,
			tokenEndpoint: "https://dsts.contoso.example/dstsv2/" + DSTSTenant + "/oauth2/v2.0/token",
			want:          "https://dsts.contoso.example/dstsv2/" + DSTSTenant + "/oauth2/v2.0/token",
		},
		{
			desc:          "the scheme is pinned to https and userinfo is stripped",
			authority:     "https://dsts.core.windows.net/dstsv2/" + DSTSTenant,
			tokenEndpoint: "http://attacker:pw@dsts.core.windows.net/dstsv2/" + DSTSTenant + "/oauth2/v2.0/token",
			want:          "https://dsts.core.windows.net/dstsv2/" + DSTSTenant + "/oauth2/v2.0/token",
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			info, err := NewInfoFromAuthorityURI(test.authority, true, false)
			if err != nil {
				t.Fatalf("NewInfoFromAuthorityURI(%q): %v", test.authority, err)
			}
			if info.AuthorityType != DSTS {
				t.Fatalf("AuthorityType = %q, want %q; this case no longer tests what it claims to", info.AuthorityType, DSTS)
			}
			p := AuthParams{AuthorityInfo: info, Endpoints: Endpoints{TokenEndpoint: test.tokenEndpoint}}
			if test.region != "" {
				p.AuthorityInfo.Region = test.region
			}
			got, err := p.MtlsTokenEndpoint()
			if err != nil {
				t.Fatalf("MtlsTokenEndpoint() unexpected error: %v", err)
			}
			if got != test.want {
				t.Errorf("MtlsTokenEndpoint() = %q, want %q", got, test.want)
			}
			if strings.Contains(got, mtlsAuthPrefix) {
				t.Errorf("MtlsTokenEndpoint() = %q, a dSTS authority must not be rewritten to %s.*", got, mtlsAuthPrefix)
			}
		})
	}

	// Without a resolved token endpoint there is nothing to keep and no AAD-shaped path to fall back
	// to, so this fails closed rather than sending the binding certificate to a guessed URL.
	t.Run("an unresolved token endpoint is an error", func(t *testing.T) {
		info, err := NewInfoFromAuthorityURI("https://dsts.core.windows.net/dstsv2/"+DSTSTenant, true, false)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := (AuthParams{AuthorityInfo: info}).MtlsTokenEndpoint(); err == nil {
			t.Fatalf("MtlsTokenEndpoint() = %q, want an error when the token endpoint is unresolved", got)
		}
	})
}

// TestMtlsTokenEndpointRequiresTrustedHostMetadata pins that the login -> mtlsauth rewrite happens
// only for a host backed by trusted cloud metadata, or for a private cloud whose caller made an
// explicit trust decision.
//
// Without the gate the swap is unconditional, so any attacker-influenced authority derives a
// matching mtlsauth host and MSAL presents the binding certificate - and, on the FIC path, a live
// client assertion - to whatever that host resolves to.
//
// The control at the top proves the params are otherwise acceptable, so each case varies exactly one
// thing: first the host, then, for the same untrusted host, only InstanceDiscoveryDisabled.
func TestMtlsTokenEndpointRequiresTrustedHostMetadata(t *testing.T) {
	const tenant = "contoso.onmicrosoft.com"

	got, err := mtlsParams(defaultHost, tenant, "", "").MtlsTokenEndpoint()
	if err != nil {
		t.Fatalf("the trusted-host control was rejected: %v", err)
	}
	if want := "https://" + publicMtlsAuthHost + "/" + tenant + "/oauth2/v2.0/token"; got != want {
		t.Fatalf("the trusted-host control derived %q, want %q", got, want)
	}

	for _, host := range []string{
		"login.evil.test",
		"login.example.com",
		// Not a suffix or substring match: this contains a trusted host but is not one.
		"login.microsoftonline.com.evil.test",
		"login.contoso.internal:9443",
	} {
		t.Run(host, func(t *testing.T) {
			got, err := mtlsParams(host, tenant, "", "").MtlsTokenEndpoint()
			if err == nil {
				t.Fatalf("MtlsTokenEndpoint() = %q, want an untrusted host to be refused", got)
			}
			msg := err.Error()
			if !strings.Contains(msg, "not a known Microsoft cloud host") {
				t.Errorf("error %q did not come from the host-trust guard", msg)
			}
			if !strings.Contains(msg, host) {
				t.Errorf("error %q does not name the offending host %q", msg, host)
			}

			// Exactly one field differs from the rejected params above: the caller's explicit
			// private-cloud trust decision.
			got, err = mtlsPrivateCloudParams(host, tenant, "", "").MtlsTokenEndpoint()
			if err != nil {
				t.Fatalf("a private cloud that opted in with WithInstanceDiscovery(false) was refused: %v", err)
			}
			want := "https://" + mtlsAuthPrefix + strings.TrimPrefix(host, loginPrefix) + "/" + tenant + "/oauth2/v2.0/token"
			if got != want {
				t.Errorf("MtlsTokenEndpoint() = %q, want %q", got, want)
			}
		})
	}
}

// TestMtlsPoPTrustedHostsNeedNoOptIn is the breadth control for the host-trust guard: every host the
// library already trusts must still work with instance discovery left on, so the guard can't pass by
// refusing everything it doesn't have a test for. This is the property MSAL .NET's #6153 lost, where
// extra host rejection broke SN/I mTLS PoP in Azure China.
func TestMtlsPoPTrustedHostsNeedNoOptIn(t *testing.T) {
	trusted := 0
	for host := range aadTrustedHostList {
		if !strings.HasPrefix(host, loginPrefix+".") {
			// sts.windows.net and login-us.microsoftonline.com are trusted but aren't login.*
			// hosts, so the prefix guard refuses them before trust is consulted.
			continue
		}
		trusted++
		t.Run(host, func(t *testing.T) {
			params := mtlsParams(host, "contoso.onmicrosoft.com", "", "")
			if params.AuthorityInfo.InstanceDiscoveryDisabled {
				t.Fatal("this control must run with instance discovery enabled")
			}
			got, err := params.MtlsTokenEndpoint()
			if err != nil {
				t.Fatalf("trusted host %q was refused without an opt-in: %v", host, err)
			}
			if !strings.Contains(got, "//"+mtlsAuthPrefix+".") {
				t.Errorf("trusted host %q derived %q, want an mtlsauth.* host", host, got)
			}
		})
	}
	if trusted < 10 {
		t.Errorf("only %d trusted login.* hosts were exercised; the trusted host list looks truncated", trusted)
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
// hardcoded block list rejected sovereign hosts outright. An arbitrary login.* host is deliberately
// absent: it is no longer supported unconditionally, and TestMtlsTokenEndpointRequiresTrustedHostMetadata
// covers it with and without the private-cloud opt-in.
func TestMtlsPoPKnownSovereignHostsSupported(t *testing.T) {
	for _, host := range []string{
		"login.microsoftonline.com", "login.microsoft.com", "login.windows.net",
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

// TestMtlsTokenEndpointRejectsInvalidRegion pins the region check at the point of use. The region is
// concatenated straight onto the mtlsauth host, so it must be a DNS label before it gets there.
//
// AADInstanceDiscovery applies the same check, and today every non-empty region reaches it first via
// resolvers.go, so nothing here is reachable from the public API. That ordering is a property of the
// resolver, not a guarantee this function makes, which is why the check is duplicated here and why
// this test drives MtlsTokenEndpoint directly instead of going through a client.
func TestMtlsTokenEndpointRejectsInvalidRegion(t *testing.T) {
	for _, region := range []string{
		"hostile.example/x",     // path separator: escapes the host entirely
		"evil.example",          // extra label
		"westus:8443",           // port
		"WestUS",                // uppercase is not a region name
		"-westus",               // leading hyphen is not a valid DNS label
		"westus-",               // trailing hyphen is not a valid DNS label
		"west us",               // space
		strings.Repeat("a", 64), // one label, but longer than 63 characters
	} {
		t.Run(region, func(t *testing.T) {
			params := mtlsParams("login.microsoftonline.com", "contoso.onmicrosoft.com", region,
				"https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token")
			got, err := params.MtlsTokenEndpoint()
			if err == nil {
				t.Fatalf("MtlsTokenEndpoint() with region %q = %q, want an error", region, got)
			}
			if !strings.Contains(err.Error(), "invalid region") {
				t.Errorf("MtlsTokenEndpoint() error = %v, want an invalid region error", err)
			}
			if got != "" {
				t.Errorf("MtlsTokenEndpoint() returned %q alongside an error", got)
			}
		})
	}
}

// TestMtlsTokenEndpointPinsSchemeAndDropsUserinfo covers the fields the host rewrite used to inherit
// from the tenant discovery document. TenantDiscoveryResponse.Validate only checks that
// token_endpoint is non-empty, so its scheme and userinfo are untrusted input: an http:// endpoint
// would produce an http:// mTLS endpoint, where no handshake runs and the certificate binding is
// silently void, and userinfo would survive into an Authorization: Basic header added by net/http.
func TestMtlsTokenEndpointPinsSchemeAndDropsUserinfo(t *testing.T) {
	for _, test := range []struct {
		name          string
		tokenEndpoint string
		want          string
	}{
		{
			name:          "http scheme is replaced with https",
			tokenEndpoint: "http://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
			want:          "https://mtlsauth.microsoft.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:          "userinfo is dropped",
			tokenEndpoint: "https://user:pass@login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
			want:          "https://mtlsauth.microsoft.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
		},
		{
			name:          "http and userinfo together",
			tokenEndpoint: "http://user:pass@login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token?p=1",
			want:          "https://mtlsauth.microsoft.com/contoso.onmicrosoft.com/oauth2/v2.0/token?p=1",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := mtlsParams("login.microsoftonline.com", "contoso.onmicrosoft.com", "", test.tokenEndpoint).MtlsTokenEndpoint()
			if err != nil {
				t.Fatalf("MtlsTokenEndpoint() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("MtlsTokenEndpoint() = %q, want %q", got, test.want)
			}
			u, err := url.Parse(got)
			if err != nil {
				t.Fatalf("parsing the derived endpoint failed: %v", err)
			}
			if u.Scheme != "https" {
				t.Errorf("derived endpoint scheme = %q, want https", u.Scheme)
			}
			if u.User != nil {
				t.Errorf("derived endpoint carries userinfo %q", u.User)
			}
			if u.Host != publicMtlsAuthHost {
				t.Errorf("derived endpoint host = %q, want %q", u.Host, publicMtlsAuthHost)
			}
		})
	}
}
