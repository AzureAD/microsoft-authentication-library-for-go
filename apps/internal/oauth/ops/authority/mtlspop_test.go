// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

func selfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestNewMtlsPopAuthenticationScheme_ImplementsInterface(t *testing.T) {
	cert := selfSignedCert(t)
	var _ AuthenticationScheme = NewMtlsPopAuthenticationScheme(cert)
}

func TestMtlsPopAuthenticationScheme_TokenRequestParams(t *testing.T) {
	cert := selfSignedCert(t)
	scheme := NewMtlsPopAuthenticationScheme(cert)
	params := scheme.TokenRequestParams()
	if params["token_type"] != "mtls_pop" {
		t.Errorf("TokenRequestParams: want token_type=mtls_pop, got %q", params["token_type"])
	}
}

func TestMtlsPopAuthenticationScheme_AccessTokenType(t *testing.T) {
	cert := selfSignedCert(t)
	scheme := NewMtlsPopAuthenticationScheme(cert)
	if got := scheme.AccessTokenType(); got != "mtls_pop" {
		t.Errorf("AccessTokenType: want mtls_pop, got %q", got)
	}
}

func TestMtlsPopAuthenticationScheme_FormatAccessToken(t *testing.T) {
	cert := selfSignedCert(t)
	scheme := NewMtlsPopAuthenticationScheme(cert)
	token := "mytoken"
	out, err := scheme.FormatAccessToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if out != token {
		t.Errorf("FormatAccessToken: want %q, got %q", token, out)
	}
}

func TestMtlsPopAuthenticationScheme_KeyID_IsBase64URLSha256(t *testing.T) {
	cert := selfSignedCert(t)
	scheme := NewMtlsPopAuthenticationScheme(cert)
	keyID := scheme.KeyID()
	if keyID == "" {
		t.Fatal("KeyID must not be empty")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(keyID)
	if err != nil {
		t.Fatalf("KeyID is not valid base64url: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("KeyID decoded length: want 32 bytes (SHA-256), got %d", len(decoded))
	}
}

func TestMtlsPopAuthenticationScheme_KeyID_DifferentCerts(t *testing.T) {
	cert1 := selfSignedCert(t)
	cert2 := selfSignedCert(t)
	s1 := NewMtlsPopAuthenticationScheme(cert1)
	s2 := NewMtlsPopAuthenticationScheme(cert2)
	if s1.KeyID() == s2.KeyID() {
		t.Error("Different certs must produce different KeyIDs")
	}
}

// TestBuildMtlsEndpoint_PublicCloud checks public cloud endpoint format.
func TestBuildMtlsEndpoint_PublicCloud(t *testing.T) {
	info, _ := NewInfoFromAuthorityURI("https://login.microsoftonline.com/mytenant", false, false)
	endpoint, err := BuildMtlsEndpoint("eastus", "mytenant", info)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://eastus.mtlsauth.microsoft.com/mytenant/oauth2/v2.0/token"
	if endpoint != want {
		t.Errorf("BuildMtlsEndpoint public: want %q, got %q", want, endpoint)
	}
}

// TestBuildMtlsEndpoint_USGov checks US Government cloud endpoint format.
func TestBuildMtlsEndpoint_USGov(t *testing.T) {
	info := Info{
		Host:          "login.microsoftonline.us",
		AuthorityType: AAD,
		Tenant:        "mytenant",
	}
	endpoint, err := BuildMtlsEndpoint("usgovvirginia", "mytenant", info)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://usgovvirginia.mtlsauth.microsoftonline.us/mytenant/oauth2/v2.0/token"
	if endpoint != want {
		t.Errorf("BuildMtlsEndpoint USGov: want %q, got %q", want, endpoint)
	}
}

// TestBuildMtlsEndpoint_China checks China cloud endpoint format.
func TestBuildMtlsEndpoint_China(t *testing.T) {
	info := Info{
		Host:          "login.partner.microsoftonline.cn",
		AuthorityType: AAD,
		Tenant:        "mytenant",
	}
	endpoint, err := BuildMtlsEndpoint("chinanorth", "mytenant", info)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://chinanorth.mtlsauth.partner.microsoftonline.cn/mytenant/oauth2/v2.0/token"
	if endpoint != want {
		t.Errorf("BuildMtlsEndpoint China: want %q, got %q", want, endpoint)
	}
}

// TestBuildMtlsEndpoint_EmptyRegionErrors checks that an empty region for AAD is an error.
func TestBuildMtlsEndpoint_EmptyRegionErrors(t *testing.T) {
	info, _ := NewInfoFromAuthorityURI("https://login.microsoftonline.com/mytenant", false, false)
	_, err := BuildMtlsEndpoint("", "mytenant", info)
	if err == nil {
		t.Error("BuildMtlsEndpoint: expected error for empty region on AAD authority")
	}
}

// TestBuildMtlsEndpoint_DSTS checks DSTS authority uses a standard endpoint without region.
func TestBuildMtlsEndpoint_DSTS(t *testing.T) {
	info, err := NewInfoFromAuthorityURI("https://dsts.core.windows.net/dstsv2/"+DSTSTenant, false, false)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := BuildMtlsEndpoint("", DSTSTenant, info)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint == "" {
		t.Error("BuildMtlsEndpoint DSTS: should return a non-empty endpoint")
	}
}

// TestAppKey_IncludesSchemeKeyID verifies mTLS PoP tokens get a distinct cache key.
func TestAppKey_IncludesSchemeKeyID(t *testing.T) {
	cert := selfSignedCert(t)
	base := AuthParams{
		ClientID:      "client",
		AuthorityInfo: Info{Tenant: "tenant"},
		AuthnScheme:   &bearerAuthnScheme,
	}
	mtlsParams := base
	mtlsParams.AuthnScheme = NewMtlsPopAuthenticationScheme(cert)

	bearerKey := base.AppKey()
	mtlsKey := mtlsParams.AppKey()

	if bearerKey == mtlsKey {
		t.Error("mTLS PoP cache key must differ from bearer cache key")
	}
	if mtlsKey == "" {
		t.Error("mTLS PoP AppKey must not be empty")
	}
}

// TestResolveRegion_PassThrough checks that non-autodetect values are returned as-is.
func TestResolveRegion_PassThrough(t *testing.T) {
	ctx := context.Background()
	for _, region := range []string{"eastus", "westeurope", ""} {
		got := ResolveRegion(ctx, region)
		if got != region {
			t.Errorf("ResolveRegion(%q): want %q, got %q", region, region, got)
		}
	}
}

// helper to encode 4 bytes little-endian
func le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}
