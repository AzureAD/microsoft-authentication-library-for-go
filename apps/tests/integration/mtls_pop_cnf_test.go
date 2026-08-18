// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"
)

// unsignedJWT builds a token with the given payload. checkTokenBoundToCertificate never verifies the
// signature - it only reads the cnf claim - so an unsigned token is sufficient and keeps the test
// free of any key material.
func unsignedJWT(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc([]byte(payload)) + ".signature"
}

func testLeaf(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "cnf-check-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func thumbprintOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestCheckTokenBoundToCertificate is the negative control for the cnf assertion that
// requireTokenAcceptedByResource now makes. The live E2E can only ever exercise the happy path, so
// without this the assertion could be silently vacuous - for example if the claim were missing and
// the check treated that as success. This test runs anywhere: it needs no lab certificate and no
// network.
func TestCheckTokenBoundToCertificate(t *testing.T) {
	bound := testLeaf(t, 1)
	other := testLeaf(t, 2)

	if thumbprintOf(bound) == thumbprintOf(other) {
		t.Fatal("the two test certificates hash identically; the test proves nothing")
	}

	for _, test := range []struct {
		desc    string
		token   string
		cert    *x509.Certificate
		wantErr string
	}{
		{
			desc:  "bound to the certificate",
			token: unsignedJWT(`{"cnf":{"x5t#S256":"` + thumbprintOf(bound) + `"}}`),
			cert:  bound,
		},
		{
			desc:    "bound to a different certificate",
			token:   unsignedJWT(`{"cnf":{"x5t#S256":"` + thumbprintOf(other) + `"}}`),
			cert:    bound,
			wantErr: "bound to a different certificate",
		},
		{
			desc:    "no cnf claim at all",
			token:   unsignedJWT(`{"aud":"https://vault.azure.net"}`),
			cert:    bound,
			wantErr: "not certificate-bound",
		},
		{
			desc:    "cnf present but empty",
			token:   unsignedJWT(`{"cnf":{}}`),
			cert:    bound,
			wantErr: "not certificate-bound",
		},
		{
			desc:    "not a JWT",
			token:   "opaque-access-token",
			cert:    bound,
			wantErr: "not a JWT",
		},
		{
			desc:    "payload is not base64url",
			token:   "header.!!!not-base64!!!.signature",
			cert:    bound,
			wantErr: "decoding the JWT payload failed",
		},
		{
			desc:    "payload is not JSON",
			token:   unsignedJWT("not json"),
			cert:    bound,
			wantErr: "parsing the JWT payload failed",
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			err := checkTokenBoundToCertificate(test.token, test.cert)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("checkTokenBoundToCertificate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("checkTokenBoundToCertificate() = nil, want an error containing %q", test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, test.wantErr)
			}
		})
	}
}
