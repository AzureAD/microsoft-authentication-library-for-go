// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package accesstokens

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// errSigner is a crypto.Signer that always fails, to check the error is surfaced rather than swallowed.
type errSigner struct {
	pub crypto.PublicKey
}

func (e errSigner) Public() crypto.PublicKey { return e.pub }

func (e errSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("the key store said no")
}

func TestNewSignerMethod(t *testing.T) {
	t.Run("PS256", func(t *testing.T) {
		m, err := newSignerMethod(jwt.SigningMethodPS256)
		if err != nil {
			t.Fatal(err)
		}
		opts, ok := m.opts.(*rsa.PSSOptions)
		if !ok {
			t.Fatalf("opts is %T, want *rsa.PSSOptions", m.opts)
		}
		// jwt.SigningMethodPS256 signs with PSSSaltLengthEqualsHash; anything else changes the wire format
		if want := jwt.SigningMethodPS256.Options.SaltLength; opts.SaltLength != want {
			t.Errorf("SaltLength = %d, want %d (jwt.SigningMethodPS256's)", opts.SaltLength, want)
		}
		if opts.SaltLength != rsa.PSSSaltLengthEqualsHash {
			t.Errorf("SaltLength = %d, want rsa.PSSSaltLengthEqualsHash", opts.SaltLength)
		}
		// crypto.Signer implementations get the hash only from opts, so it must be set
		if opts.Hash != crypto.SHA256 {
			t.Errorf("Hash = %v, want SHA-256", opts.Hash)
		}
		if m.opts.HashFunc() != crypto.SHA256 {
			t.Errorf("HashFunc() = %v, want SHA-256", m.opts.HashFunc())
		}
	})
	t.Run("RS256", func(t *testing.T) {
		m, err := newSignerMethod(jwt.SigningMethodRS256)
		if err != nil {
			t.Fatal(err)
		}
		// PKCS #1 v1.5 signers take the bare hash
		if m.opts != crypto.SignerOpts(crypto.SHA256) {
			t.Errorf("opts = %v (%T), want crypto.SHA256", m.opts, m.opts)
		}
	})
	t.Run("unsupported", func(t *testing.T) {
		for _, method := range []jwt.SigningMethod{jwt.SigningMethodES256, jwt.SigningMethodPS384, jwt.SigningMethodRS512, jwt.SigningMethodHS256} {
			if _, err := newSignerMethod(method); err == nil {
				t.Errorf("expected an error for %s", method.Alg())
			}
		}
	})
}

func TestSignerMethodAlg(t *testing.T) {
	for _, method := range []jwt.SigningMethod{jwt.SigningMethodPS256, jwt.SigningMethodRS256} {
		m, err := newSignerMethod(method)
		if err != nil {
			t.Fatal(err)
		}
		// the alg header and thumbprint() both key off this, so it must be the wrapped method's
		if m.Alg() != method.Alg() {
			t.Errorf("Alg() = %q, want %q", m.Alg(), method.Alg())
		}
	}
}

// TestSignerMethodSignRS256Equivalence pins the signer path to the built-in method: PKCS #1 v1.5 is
// deterministic, so the signatures must be byte identical for the same input.
func TestSignerMethodSignRS256Equivalence(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m, err := newSignerMethod(jwt.SigningMethodRS256)
	if err != nil {
		t.Fatal(err)
	}
	signingString := "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJjbGllbnQifQ"
	want, err := jwt.SigningMethodRS256.Sign(signingString, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Sign(signingString, &signerOnlyRSAKey{key: key})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Error("the signer method's RS256 signature isn't what jwt.SigningMethodRS256 produces")
	}
}

// TestSignerMethodSignPS256 verifies the PSS signature strictly, i.e. with the salt length
// jwt.SigningMethodPS256 uses rather than PSSSaltLengthAuto, which accepts any salt.
func TestSignerMethodSignPS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m, err := newSignerMethod(jwt.SigningMethodPS256)
	if err != nil {
		t.Fatal(err)
	}
	signingString := "eyJhbGciOiJQUzI1NiJ9.eyJpc3MiOiJjbGllbnQifQ"
	sig, err := m.Sign(signingString, &signerOnlyRSAKey{key: key})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(signingString))
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], sig, opts); err != nil {
		t.Fatalf("the signature doesn't verify with jwt.SigningMethodPS256's salt length: %v", err)
	}
}

// TestSignerMethodSignHashesSigningString verifies the signer receives the digest of the signing
// string, not the signing string itself.
func TestSignerMethodSignHashesSigningString(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []jwt.SigningMethod{jwt.SigningMethodPS256, jwt.SigningMethodRS256} {
		t.Run(method.Alg(), func(t *testing.T) {
			m, err := newSignerMethod(method)
			if err != nil {
				t.Fatal(err)
			}
			signer := &signerOnlyRSAKey{key: key}
			signingString := "signing.string"
			if _, err := m.Sign(signingString, signer); err != nil {
				t.Fatal(err)
			}
			if signer.calls != 1 {
				t.Fatalf("the signer was called %d times, want 1", signer.calls)
			}
			want := sha256.Sum256([]byte(signingString))
			if string(signer.digest) != string(want[:]) {
				t.Error("the signer didn't get the SHA-256 digest of the signing string")
			}
		})
	}
}

// TestSignerMethodVerify verifies validation still works, using the public key, through the wrapper.
func TestSignerMethodVerify(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []jwt.SigningMethod{jwt.SigningMethodPS256, jwt.SigningMethodRS256} {
		t.Run(method.Alg(), func(t *testing.T) {
			m, err := newSignerMethod(method)
			if err != nil {
				t.Fatal(err)
			}
			signingString := "eyJhbGciOiJ4In0.eyJpc3MiOiJjbGllbnQifQ"
			sig, err := m.Sign(signingString, &signerOnlyRSAKey{key: key})
			if err != nil {
				t.Fatal(err)
			}
			if err := m.Verify(signingString, sig, &key.PublicKey); err != nil {
				t.Fatalf("a signature from the signer method must verify through it: %v", err)
			}
			// the built-in method must accept it too, because that's what a server does
			if err := method.Verify(signingString, sig, &key.PublicKey); err != nil {
				t.Fatalf("a signature from the signer method must verify with %s: %v", method.Alg(), err)
			}
			if err := m.Verify(signingString+"tampered", sig, &key.PublicKey); err == nil {
				t.Error("expected an error verifying a signature over different content")
			}
		})
	}
}

func TestSignerMethodSignError(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m, err := newSignerMethod(jwt.SigningMethodPS256)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("key isn't a signer", func(t *testing.T) {
		if _, err := m.Sign("signing.string", "not a signer"); !errors.Is(err, jwt.ErrInvalidKeyType) {
			t.Errorf("err = %v, want jwt.ErrInvalidKeyType", err)
		}
	})
	t.Run("the signer fails", func(t *testing.T) {
		if _, err := m.Sign("signing.string", errSigner{pub: &key.PublicKey}); err == nil {
			t.Error("expected the signer's error to be surfaced")
		}
	})
}
