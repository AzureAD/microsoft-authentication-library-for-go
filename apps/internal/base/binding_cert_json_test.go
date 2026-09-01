// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package base

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"
)

// rsaBindingCert builds a throwaway self-signed certificate backed by an exportable *rsa.PrivateKey.
// That is exactly what NewCredFromCert produces today, which is what makes the JSON hazard real:
// encoding/json happily walks an *rsa.PrivateKey's exported fields.
func rsaBindingCert(t *testing.T) (*tls.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "binding-cert-json-test"},
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
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, key
}

// keyMaterialIndicators returns strings that must never appear in serialized output. big.Int
// marshals as a bare decimal number, so the private exponent and each prime are searched for in that
// form; the struct field names cover a serializer that emits them some other way.
func keyMaterialIndicators(key *rsa.PrivateKey) map[string]string {
	out := map[string]string{
		"private exponent D":  key.D.String(),
		`"PrivateKey" field`:  `"PrivateKey"`,
		`"Primes" field`:      `"Primes"`,
		`"Precomputed" field`: `"Precomputed"`,
	}
	for i, p := range key.Primes {
		out["prime "+strconv.Itoa(i)] = p.String()
	}
	return out
}

// TestAuthResultJSONExcludesBindingCertificate is the regression test for the json:"-" tag on
// AuthResult.BindingCertificate. Without the tag, marshalling an AuthResult (a log line, a trace, a
// diagnostic dump) writes the binding certificate's private exponent and primes out in the clear,
// because encoding/json recurses into *rsa.PrivateKey's exported fields.
func TestAuthResultJSONExcludesBindingCertificate(t *testing.T) {
	cert, key := rsaBindingCert(t)
	ar := AuthResult{
		AccessToken:   "at",
		GrantedScopes: []string{"scope"},
		Metadata: AuthResultMetadata{
			TokenType:   "mtls_pop",
			TokenSource: TokenSourceIdentityProvider,
		},
		BindingCertificate: cert,
	}

	b, err := json.Marshal(ar)
	if err != nil {
		t.Fatalf("json.Marshal(AuthResult) failed: %s", err)
	}
	got := string(b)

	for name, needle := range keyMaterialIndicators(key) {
		if strings.Contains(got, needle) {
			t.Errorf("marshalled AuthResult leaks %s", name)
		}
	}
	// The whole field must be gone, not merely emptied.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatalf("unmarshalling the result failed: %s", err)
	}
	if _, ok := fields["BindingCertificate"]; ok {
		t.Error("BindingCertificate is still serialized")
	}
	// Sanity check that the rest of the result still round-trips, so the tag didn't silently break
	// serialization of AuthResult as a whole.
	if !strings.Contains(got, `"AccessToken":"at"`) {
		t.Errorf("AuthResult no longer serializes its other fields: %s", got)
	}
}

// TestAuthResultJSONIndicatorsAreReal proves the assertions above can actually fail. It marshals the
// same certificate through a struct WITHOUT the json:"-" tag and requires every indicator to show up.
// If encoding/json ever stopped walking into *rsa.PrivateKey, the test above would pass vacuously and
// this one would catch that.
func TestAuthResultJSONIndicatorsAreReal(t *testing.T) {
	cert, key := rsaBindingCert(t)
	untagged := struct {
		BindingCertificate *tls.Certificate
	}{BindingCertificate: cert}

	b, err := json.Marshal(untagged)
	if err != nil {
		t.Fatalf("json.Marshal failed: %s", err)
	}
	got := string(b)
	for name, needle := range keyMaterialIndicators(key) {
		if !strings.Contains(got, needle) {
			t.Errorf("untagged serialization did not contain %s, so the leak assertions are not proving anything", name)
		}
	}
}

// TestBindingCertWithLeafDeepCopiesDER pins the deep copy of the DER chain. The source
// *tls.Certificate here models the one retained by the per-thumbprint mTLS client cache in
// oauth/ops/internal/comm: with a shallow copy, a caller mutating
// result.BindingCertificate.Certificate[0] rewrites the bytes that cached certificate presents on
// every subsequent (or in-flight) TLS handshake.
func TestBindingCertWithLeafDeepCopiesDER(t *testing.T) {
	leaf, key := selfSignedCert(t)
	extra := []byte{0x30, 0x00, 0x11, 0x22}

	for _, test := range []struct {
		desc     string
		withLeaf bool
	}{
		{desc: "leaf already set", withLeaf: true},
		{desc: "leaf parsed from DER", withLeaf: false},
	} {
		t.Run(test.desc, func(t *testing.T) {
			source := &tls.Certificate{
				Certificate: [][]byte{append([]byte(nil), leaf.Raw...), append([]byte(nil), extra...)},
				PrivateKey:  key,
			}
			if test.withLeaf {
				source.Leaf = leaf
			}
			want := [][]byte{append([]byte(nil), source.Certificate[0]...), append([]byte(nil), source.Certificate[1]...)}

			got := bindingCertWithLeaf(source)
			if got == nil {
				t.Fatal("bindingCertWithLeaf returned nil")
			}
			if len(got.Certificate) != len(source.Certificate) {
				t.Fatalf("got %d DER entries, want %d", len(got.Certificate), len(source.Certificate))
			}
			if &got.Certificate[0] == &source.Certificate[0] {
				t.Fatal("the returned chain shares its outer slice with the cached certificate")
			}
			for i := range got.Certificate {
				if !bytes.Equal(got.Certificate[i], want[i]) {
					t.Fatalf("DER entry %d was not copied faithfully", i)
				}
				if &got.Certificate[i][0] == &source.Certificate[i][0] {
					t.Fatalf("DER entry %d shares its backing array with the cached certificate", i)
				}
			}

			// The reviewer's reproduction: mutate through the result and require the cached
			// certificate to be untouched.
			for i := range got.Certificate {
				got.Certificate[i][0] ^= 0xFF
			}
			for i := range source.Certificate {
				if !bytes.Equal(source.Certificate[i], want[i]) {
					t.Fatalf("mutating the returned DER changed cached entry %d; a later handshake would present corrupted DER", i)
				}
			}

			// PrivateKey is shared on purpose: callers need the live signer, and a non-exportable
			// key cannot be copied at all.
			if got.PrivateKey != crypto.PrivateKey(key) {
				t.Error("PrivateKey must remain the live signer MSAL used for the token request")
			}
		})
	}
}

// TestBindingCertificateDirectSerializationLeaks pins the limit of the json:"-" tag, which protects
// AuthResult and nothing else.
//
// Marshalling the *tls.Certificate on its own reaches the private key, so the field is
// secret-bearing in its own right and the doc comment says so. This test exists to keep that
// statement true: if encoding/json ever stopped walking into the key, the tag would still be correct
// but the warning would be stale.
//
// It also records that fmt is not equivalent protection. %v, %+v and %#v do not reach the key, but
// only because fmt prints a nested pointer as an address -- a logger that serializes structs rather
// than formatting them gets the marshalling behavior instead.
func TestBindingCertificateDirectSerializationLeaks(t *testing.T) {
	cert, key := rsaBindingCert(t)
	indicators := keyMaterialIndicators(key)

	b, err := json.Marshal(cert)
	if err != nil {
		t.Fatalf("json.Marshal failed: %s", err)
	}
	direct := string(b)
	for name, needle := range indicators {
		if !strings.Contains(direct, needle) {
			t.Errorf("marshalling the certificate directly no longer emits %s; the doc comment warning on AuthResult.BindingCertificate is now stale", name)
		}
	}

	// The same certificate reached through an AuthResult stays protected, so the tag is doing its job.
	ar := AuthResult{AccessToken: "at", BindingCertificate: cert}
	b, err = json.Marshal(ar)
	if err != nil {
		t.Fatalf("json.Marshal(AuthResult) failed: %s", err)
	}
	for name, needle := range indicators {
		if strings.Contains(string(b), needle) {
			t.Errorf("marshalling the AuthResult leaks %s", name)
		}
	}

	// fmt does not reach the key. Asserted so a change in that behavior is noticed rather than
	// discovered in a log.
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		formatted := fmt.Sprintf(verb, cert)
		for name, needle := range indicators {
			if strings.Contains(formatted, needle) {
				t.Errorf("fmt %s on the certificate now emits %s; the doc comment should be updated to warn about formatting too", verb, name)
			}
		}
	}
}
