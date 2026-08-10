// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package accesstokens

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"

	/* #nosec */
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/golang-jwt/jwt/v5"
)

// signerOnlyRSAKey stands in for a non-exportable key such as a Windows KeyGuard (VBS-isolated) key:
// it satisfies crypto.Signer by delegating to an RSA key it never exposes, so no code can type assert
// it to an *rsa.PrivateKey. Tests using it therefore run anywhere, without CNG. It records what it
// was asked to sign so tests can assert the digest and options reaching a real key store.
type signerOnlyRSAKey struct {
	key    *rsa.PrivateKey
	calls  int
	opts   crypto.SignerOpts
	digest []byte
}

func (s *signerOnlyRSAKey) Public() crypto.PublicKey { return &s.key.PublicKey }

func (s *signerOnlyRSAKey) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	s.opts = opts
	s.digest = append([]byte(nil), digest...)
	return s.key.Sign(r, digest, opts)
}

// signerOnlyECKey is the same idea for an ECDSA key, which a credential can hold because
// NewCredFromTLSCertificate validates the signer against the leaf rather than requiring RSA.
type signerOnlyECKey struct {
	key *ecdsa.PrivateKey
}

func (s signerOnlyECKey) Public() crypto.PublicKey { return &s.key.PublicKey }

func (s signerOnlyECKey) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(r, digest, opts)
}

func selfSignedCert(t *testing.T, cn string, key *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
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

// assertionFixture returns a leaf certificate, the RSA key it belongs to, and an x5c chain holding
// the leaf plus another certificate so chain-order assertions are meaningful.
func assertionFixture(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	leaf := selfSignedCert(t, "assertion-test-leaf", key)
	issuer := selfSignedCert(t, "assertion-test-issuer", issuerKey)
	x5c := []string{
		base64.StdEncoding.EncodeToString(leaf.Raw),
		base64.StdEncoding.EncodeToString(issuer.Raw),
	}
	return leaf, key, x5c
}

func assertionAuthParams(authorityType string, sendX5C bool) authority.AuthParams {
	return authority.AuthParams{
		AuthorityInfo: authority.Info{
			Host:          "login.microsoftonline.com",
			Tenant:        "mytenant",
			AuthorityType: authorityType,
		},
		Endpoints: authority.NewEndpoints(
			"https://login.microsoftonline.com/mytenant/oauth2/v2.0/authorize",
			"https://login.microsoftonline.com/mytenant/oauth2/v2.0/token",
			"https://login.microsoftonline.com/mytenant/v2.0",
			"login.microsoftonline.com",
		),
		ClientID: "clientID",
		Scopes:   []string{"scope"},
		SendX5C:  sendX5C,
	}
}

// decodeAssertion splits a JWT into its decoded header, decoded claims, raw signing string and
// signature bytes.
func decodeAssertion(t *testing.T, assertion string) (map[string]interface{}, map[string]interface{}, string, []byte) {
	t.Helper()
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion has %d segments, want 3", len(parts))
	}
	decode := func(s string) map[string]interface{} {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("decoding %q: %v", s, err)
		}
		m := map[string]interface{}{}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("unmarshaling %q: %v", string(b), err)
		}
		return m
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding the signature: %v", err)
	}
	return decode(parts[0]), decode(parts[1]), parts[0] + "." + parts[1], sig
}

// TestJWTSignerOnlyPS256 covers the default (AAD) case: a non-exportable key must produce a PS256
// assertion that verifies against the certificate's public key, with the salt length
// jwt.SigningMethodPS256 uses.
func TestJWTSignerOnlyPS256(t *testing.T) {
	leaf, key, x5c := assertionFixture(t)
	signer := &signerOnlyRSAKey{key: key}
	cred := &Credential{Cert: leaf, Key: signer, X5c: x5c, SignerOnly: true}

	assertion, err := cred.JWT(context.Background(), assertionAuthParams(authority.AAD, false))
	if err != nil {
		t.Fatal(err)
	}

	header, claims, signingString, sig := decodeAssertion(t, assertion)
	if header["alg"] != "PS256" {
		t.Errorf(`alg = %v, want "PS256"`, header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf(`typ = %v, want "JWT"`, header["typ"])
	}
	wantThumbprint := sha256.Sum256(leaf.Raw)
	if got := header["x5t#S256"]; got != base64.StdEncoding.EncodeToString(wantThumbprint[:]) {
		t.Errorf("x5t#S256 = %v, want the SHA-256 thumbprint of the certificate", got)
	}
	if _, ok := header["x5c"]; ok {
		t.Error("x5c must be omitted when SendX5C is false")
	}
	if claims["aud"] != "https://login.microsoftonline.com/mytenant/oauth2/v2.0/token" {
		t.Errorf("aud = %v, want the token endpoint", claims["aud"])
	}
	if claims["iss"] != "clientID" || claims["sub"] != "clientID" {
		t.Errorf("iss = %v and sub = %v, want the client ID", claims["iss"], claims["sub"])
	}

	// verify strictly: jwt's PS256 VerifyOptions use PSSSaltLengthAuto, which accepts any salt length
	digest := sha256.Sum256([]byte(signingString))
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], sig, opts); err != nil {
		t.Fatalf("the assertion doesn't verify against the certificate's public key: %v", err)
	}
	// and as a relying party would, through the JWT library
	if err := jwt.SigningMethodPS256.Verify(signingString, sig, &key.PublicKey); err != nil {
		t.Fatalf("jwt.SigningMethodPS256 rejects the assertion: %v", err)
	}

	if signer.calls != 1 {
		t.Errorf("the signer was called %d times, want 1", signer.calls)
	}
	pssOpts, ok := signer.opts.(*rsa.PSSOptions)
	if !ok {
		t.Fatalf("the signer got %T, want *rsa.PSSOptions", signer.opts)
	}
	if pssOpts.SaltLength != rsa.PSSSaltLengthEqualsHash {
		t.Errorf("the signer got SaltLength %d, want rsa.PSSSaltLengthEqualsHash", pssOpts.SaltLength)
	}
	if pssOpts.Hash != crypto.SHA256 {
		t.Errorf("the signer got Hash %v, want SHA-256", pssOpts.Hash)
	}
}

// TestJWTSignerOnlyRS256 covers the ADFS and dSTS branch, which signs PKCS #1 v1.5 with a SHA-1
// thumbprint.
func TestJWTSignerOnlyRS256(t *testing.T) {
	for _, authorityType := range []string{authority.ADFS, authority.DSTS} {
		t.Run(authorityType, func(t *testing.T) {
			leaf, key, x5c := assertionFixture(t)
			signer := &signerOnlyRSAKey{key: key}
			cred := &Credential{Cert: leaf, Key: signer, X5c: x5c, SignerOnly: true}

			assertion, err := cred.JWT(context.Background(), assertionAuthParams(authorityType, false))
			if err != nil {
				t.Fatal(err)
			}

			header, _, signingString, sig := decodeAssertion(t, assertion)
			if header["alg"] != "RS256" {
				t.Errorf(`alg = %v, want "RS256"`, header["alg"])
			}
			if header["typ"] != "JWT" {
				t.Errorf(`typ = %v, want "JWT"`, header["typ"])
			}
			wantThumbprint := sha1.Sum(leaf.Raw) /* #nosec */
			if got := header["x5t"]; got != base64.StdEncoding.EncodeToString(wantThumbprint[:]) {
				t.Errorf("x5t = %v, want the SHA-1 thumbprint of the certificate", got)
			}
			if _, ok := header["x5t#S256"]; ok {
				t.Error("the ADFS/dSTS assertion must carry x5t, not x5t#S256")
			}

			digest := sha256.Sum256([]byte(signingString))
			if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
				t.Fatalf("the assertion doesn't verify against the certificate's public key: %v", err)
			}
			if err := jwt.SigningMethodRS256.Verify(signingString, sig, &key.PublicKey); err != nil {
				t.Fatalf("jwt.SigningMethodRS256 rejects the assertion: %v", err)
			}

			if signer.opts != crypto.SignerOpts(crypto.SHA256) {
				t.Errorf("the signer got opts %v (%T), want crypto.SHA256", signer.opts, signer.opts)
			}
		})
	}
}

// TestJWTSignerOnlyWireFormat is the regression guard: for the same input, a signer-only credential
// must produce exactly the header an *rsa.PrivateKey credential does, byte for byte.
func TestJWTSignerOnlyWireFormat(t *testing.T) {
	for _, authorityType := range []string{authority.AAD, authority.ADFS, authority.DSTS} {
		for _, sendX5C := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/x5c=%v", authorityType, sendX5C), func(t *testing.T) {
				leaf, key, x5c := assertionFixture(t)
				authParams := assertionAuthParams(authorityType, sendX5C)
				keyCred := &Credential{Cert: leaf, Key: key, X5c: x5c}
				signerCred := &Credential{Cert: leaf, Key: &signerOnlyRSAKey{key: key}, X5c: x5c, SignerOnly: true}

				want, err := keyCred.JWT(context.Background(), authParams)
				if err != nil {
					t.Fatal(err)
				}
				got, err := signerCred.JWT(context.Background(), authParams)
				if err != nil {
					t.Fatal(err)
				}

				// the header is deterministic (Go sorts map keys when marshaling), so the encoded
				// segments must match exactly; the claims carry a random jti and timestamps
				wantSegment := strings.Split(want, ".")[0]
				gotSegment := strings.Split(got, ".")[0]
				if gotSegment != wantSegment {
					t.Errorf("encoded header = %q, want %q", gotSegment, wantSegment)
				}
				wantHeader, _, _, _ := decodeAssertion(t, want)
				gotHeader, _, _, _ := decodeAssertion(t, got)
				if !reflect.DeepEqual(gotHeader, wantHeader) {
					t.Errorf("header = %v, want %v", gotHeader, wantHeader)
				}
				if sendX5C {
					entries, ok := gotHeader["x5c"].([]interface{})
					if !ok {
						t.Fatalf("x5c is %T, want a list", gotHeader["x5c"])
					}
					if len(entries) != len(x5c) {
						t.Fatalf("x5c has %d entries, want %d", len(entries), len(x5c))
					}
					for i, want := range x5c {
						if entries[i] != want {
							t.Errorf("x5c[%d] isn't the credential's certificate at that position", i)
						}
					}
				} else if _, ok := gotHeader["x5c"]; ok {
					t.Error("x5c must be omitted when SendX5C is false")
				}
			})
		}
	}
}

// TestJWTPrivateKeyUnaffected verifies an exportable key still goes through jwt's built-in methods:
// the swap is gated on SignerOnly and nothing else changed.
func TestJWTPrivateKeyUnaffected(t *testing.T) {
	leaf, key, x5c := assertionFixture(t)
	cred := &Credential{Cert: leaf, Key: key, X5c: x5c}
	for _, authorityType := range []string{authority.AAD, authority.ADFS} {
		t.Run(authorityType, func(t *testing.T) {
			assertion, err := cred.JWT(context.Background(), assertionAuthParams(authorityType, true))
			if err != nil {
				t.Fatal(err)
			}
			_, _, signingString, sig := decodeAssertion(t, assertion)
			method := jwt.SigningMethod(jwt.SigningMethodPS256)
			if authorityType != authority.AAD {
				method = jwt.SigningMethodRS256
			}
			if err := method.Verify(signingString, sig, &key.PublicKey); err != nil {
				t.Fatalf("%s rejects the assertion: %v", method.Alg(), err)
			}
		})
	}
	t.Run("a signer is rejected when SignerOnly isn't set", func(t *testing.T) {
		// jwt's built-in RSA methods require an *rsa.PrivateKey. This proves JWT() hands the key
		// straight to them unless the credential says the key can't be exported.
		c := &Credential{Cert: leaf, Key: &signerOnlyRSAKey{key: key}, X5c: x5c}
		if _, err := c.JWT(context.Background(), assertionAuthParams(authority.AAD, false)); err == nil {
			t.Fatal("expected jwt's built-in method to reject a key that isn't an *rsa.PrivateKey")
		}
	})
}

// TestJWTSignerOnlyNonRSA verifies a signer ESTS can't accept still fails with actionable guidance
// rather than producing an assertion the service will reject.
func TestJWTSignerOnlyNonRSA(t *testing.T) {
	leaf, _, x5c := assertionFixture(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		key  crypto.PrivateKey
		want string
	}{
		{"ECDSA signer", signerOnlyECKey{key: ecKey}, "must be RSA"},
		{"not a signer", struct{}{}, "crypto.Signer"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cred := &Credential{Cert: leaf, Key: test.key, X5c: x5c, SignerOnly: true}
			for _, authorityType := range []string{authority.AAD, authority.ADFS} {
				_, err := cred.JWT(context.Background(), assertionAuthParams(authorityType, false))
				if err == nil {
					t.Fatalf("expected an error for %s", authorityType)
				}
				if !strings.Contains(err.Error(), test.want) {
					t.Errorf("error %q should mention %q", err, test.want)
				}
			}
		})
	}
}
