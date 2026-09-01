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
// Everything except signing delegates to the wrapped method, so the assertion is indistinguishable
// to the service from one an exportable key would produce: the same "alg" header, the same
// thumbprint header carrying the same hash, the same signature format, and the same verification
// semantics. Alg() feeds both the "alg" header and thumbprint(), and Verify needs only the public
// key. The bytes aren't identical, and can't be: PS256 salts are random, and every assertion carries
// a freshly generated jti along with nbf and exp taken from the clock.
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

// Sign hashes signingString and asks key, which must be a crypto.Signer, to sign the digest.
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
		return nil, &signerError{opts: s.opts, err: err}
	}
	return sig, nil
}

// signerError reports that crypto.Signer.Sign itself failed, as opposed to any of the other work
// that goes into producing an assertion. Its message and Unwrap behavior are what callers saw before
// it existed; the type is what lets JWT() tell a failed signing operation from a failed one.
type signerError struct {
	// opts is what the signer was given, which identifies the algorithm it was asked for.
	opts crypto.SignerOpts
	err  error
}

func (e *signerError) Error() string {
	return fmt.Sprintf("signer failed to sign the assertion: %v", e.err)
}

func (e *signerError) Unwrap() error {
	return e.err
}

// isSignerFailure reports whether err came from crypto.Signer.Sign. JWT()'s RS256 fallback is gated
// on this, because re-signing with a different algorithm can only help when the signing operation is
// what failed: assembling or marshaling the assertion fails identically whatever the algorithm.
func isSignerFailure(err error) bool {
	var se *signerError
	return errors.As(err, &se)
}
