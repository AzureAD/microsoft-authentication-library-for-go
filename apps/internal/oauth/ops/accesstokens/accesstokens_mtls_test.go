// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package accesstokens

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/internal/grant"
)

func selfSignedTLSCert(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mtls-binding-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing cert: %v", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func mtlsAuthParams(cert *tls.Certificate) authority.AuthParams {
	return authority.AuthParams{
		AuthorityInfo: authority.Info{Host: "login.microsoftonline.com", Tenant: "mytenant"},
		Endpoints: authority.NewEndpoints(
			"https://login.microsoftonline.com/mytenant/oauth2/v2.0/authorize",
			"https://login.microsoftonline.com/mytenant/oauth2/v2.0/token",
			"https://login.microsoftonline.com/mytenant/v2.0",
			"login.microsoftonline.com",
		),
		ClientID:        "clientID",
		Scopes:          []string{"scope"},
		IsMtlsPoP:       true,
		MtlsBindingCert: cert,
		AuthnScheme:     authority.NewMtlsPoPAuthenticationScheme(cert.Leaf),
	}
}

const wantMtlsEndpoint = "https://mtlsauth.microsoft.com/mytenant/oauth2/v2.0/token"

// TestFromClientCertificateMtlsPoP verifies the pure-cert mTLS PoP request: it carries
// token_type=mtls_pop, is routed to the rewritten mtlsauth endpoint with the binding certificate,
// and sends NO client_assertion and NO req_cnf (the TLS client certificate authenticates the client).
func TestFromClientCertificateMtlsPoP(t *testing.T) {
	cert := selfSignedTLSCert(t)
	authParams := mtlsAuthParams(cert)

	wantQV := url.Values{
		grantType:    []string{grant.ClientCredential},
		clientID:     []string{"clientID"},
		"token_type": []string{authority.AccessTokenTypeMtlsPoP},
	}
	addScopeQueryParam(wantQV, authParams)

	fake := &fakeURLCaller{}
	client := Client{Comm: fake, testing: true}

	if _, err := client.FromClientCertificate(context.Background(), authParams); err != nil {
		t.Fatalf("FromClientCertificate() error: %v", err)
	}

	if err := fake.compare(wantMtlsEndpoint, wantQV); err != nil {
		t.Errorf("FromClientCertificate() request mismatch: %v", err)
	}
	if _, ok := fake.gotQV["client_assertion"]; ok {
		t.Error("pure-cert mTLS request must not send client_assertion")
	}
	if _, ok := fake.gotQV["client_assertion_type"]; ok {
		t.Error("pure-cert mTLS request must not send client_assertion_type")
	}
	if _, ok := fake.gotQV["req_cnf"]; ok {
		t.Error("mTLS PoP request must not send req_cnf")
	}
	if fake.gotCert != cert {
		t.Error("FromClientCertificate did not present the binding certificate on the TLS call")
	}
}

// TestFromAssertionMtlsPoP verifies the FIC leg-2 request: it keeps client_assertion (identity) but
// marks it certificate-bound with client_assertion_type=jwt-pop, carries token_type=mtls_pop, and is
// routed to the mtlsauth endpoint with the binding certificate.
func TestFromAssertionMtlsPoP(t *testing.T) {
	cert := selfSignedTLSCert(t)
	authParams := mtlsAuthParams(cert)
	const assertion = "leg1-token"

	wantQV := url.Values{
		grantType:               []string{grant.ClientCredential},
		"client_assertion_type": []string{grant.ClientAssertionPoP},
		"client_assertion":      []string{assertion},
		clientID:                []string{"clientID"},
		clientInfo:              []string{clientInfoVal},
		"token_type":            []string{authority.AccessTokenTypeMtlsPoP},
	}
	addScopeQueryParam(wantQV, authParams)

	fake := &fakeURLCaller{}
	client := Client{Comm: fake, testing: true}

	if _, err := client.FromAssertion(context.Background(), authParams, assertion); err != nil {
		t.Fatalf("FromAssertion() error: %v", err)
	}

	if err := fake.compare(wantMtlsEndpoint, wantQV); err != nil {
		t.Errorf("FromAssertion() mTLS request mismatch: %v", err)
	}
	if got := fake.gotQV.Get("client_assertion_type"); got != grant.ClientAssertionPoP {
		t.Errorf("client_assertion_type = %q, want %q (jwt-pop)", got, grant.ClientAssertionPoP)
	}
	if fake.gotCert != cert {
		t.Error("FromAssertion mTLS did not present the binding certificate on the TLS call")
	}
}

// TestFromAssertionBearerUnchanged guards backward compatibility: without IsMtlsPoP the assertion
// path stays byte-for-byte the classic Bearer private_key_jwt request (jwt-bearer, no cert routing).
func TestFromAssertionBearerUnchanged(t *testing.T) {
	authParams := authority.AuthParams{
		Endpoints: testAuthorityEndpoints,
		ClientID:  "clientID",
		Scopes:    []string{"scope"},
	}
	const assertion = "signed-jwt"

	wantQV := url.Values{
		grantType:               []string{grant.ClientCredential},
		"client_assertion_type": []string{grant.ClientAssertion},
		"client_assertion":      []string{assertion},
		clientID:                []string{"clientID"},
		clientInfo:              []string{clientInfoVal},
	}
	addScopeQueryParam(wantQV, authParams)

	fake := &fakeURLCaller{}
	client := Client{Comm: fake, testing: true}

	if _, err := client.FromAssertion(context.Background(), authParams, assertion); err != nil {
		t.Fatalf("FromAssertion() error: %v", err)
	}
	if err := fake.compare(authParams.Endpoints.TokenEndpoint, wantQV); err != nil {
		t.Errorf("Bearer assertion request changed: %v", err)
	}
	if fake.gotCert != nil {
		t.Error("Bearer assertion request must not present a binding certificate")
	}
}
