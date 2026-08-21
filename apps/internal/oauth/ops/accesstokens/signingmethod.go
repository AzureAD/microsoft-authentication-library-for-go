// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package accesstokens

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// signerMethod adapts a jwt.SigningMethod so signing goes through a crypto.Signer instead of
// requiring an *rsa.PrivateKey. That's the only way to sign with a key whose private material can't
// be exported, such as a Windows KeyGuard (VBS-isolated) or other CNG/HSM-backed key.
//
// Everything except signing delegates to the wrapped method, so the assertion is byte-for-byte what
// an exportable key would produce: Alg() feeds both the "alg" header and thumbprint(), and Verify
// needs only the public key.
//
// Instances are constructed on demand rather than registered with jwt.RegisterSigningMethod because
// that would mutate a package-level map shared with every other user of the JWT library in the
// process.
type signerMethod struct {
	// method is the built-in method this one stands in for, and defines the wire format.
	method jwt.SigningMethod
	// opts is passed to crypto.Signer.Sign. It must produce the same signature format as method:
	// an *rsa.PSSOptions matching method's for RSA-PSS, or the bare hash for PKCS #1 v1.5.
	opts crypto.SignerOpts
}

// newSignerMethod returns a signerMethod standing in for method, which must be one of the RSA
// methods MSAL uses to sign client assertions.
func newSignerMethod(method jwt.SigningMethod) (*signerMethod, error) {
	switch method {
	case jwt.SigningMethodPS256:
		// match jwt.SigningMethodPS256's salt length exactly; PSSSaltLengthAuto would differ
		return &signerMethod{
			method: method,
			opts:   &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256},
		}, nil
	case jwt.SigningMethodRS256:
		// crypto.Signer takes the bare hash for PKCS #1 v1.5
		return &signerMethod{method: method, opts: crypto.SHA256}, nil
	default:
		return nil, fmt.Errorf("unsupported signing method %q", method.Alg())
	}
}

// Alg returns the wrapped method's algorithm name, so the assertion's "alg" header and certificate
// thumbprint are the same as they'd be without a signer.
func (s *signerMethod) Alg() string {
	return s.method.Alg()
}

// Verify delegates to the wrapped method because verification uses the public key, which is always
// available.
func (s *signerMethod) Verify(signingString string, sig []byte, key interface{}) error {
	return s.method.Verify(signingString, sig, key)
}

// Sign hashes signingString and has key, which must be a crypto.Signer, sign the digest.
func (s *signerMethod) Sign(signingString string, key interface{}) ([]byte, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, jwt.ErrInvalidKeyType
	}
	h := s.opts.HashFunc()
	if !h.Available() {
		return nil, errors.New("hash function " + h.String() + " isn't available")
	}
	hasher := h.New()
	// hash.Hash never returns an error from Write
	hasher.Write([]byte(signingString))
	sig, err := signer.Sign(rand.Reader, hasher.Sum(nil), s.opts)
	if err != nil {
		return nil, fmt.Errorf("signer failed to sign the assertion: %w", err)
	}
	return sig, nil
}
