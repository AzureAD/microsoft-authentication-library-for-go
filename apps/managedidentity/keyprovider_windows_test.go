// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build windows

package managedidentity

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"
)

// testKeyName keeps the keys these tests create separate from the one the
// library uses at runtime, so a failed run cannot disturb a real binding key.
const testKeyName = "msal-go-imdsv2-test-key"

// newTestKey mints a binding key, skipping when the host cannot isolate one.
// Credential Guard is not available on every Windows machine, notably not on
// the hosted CI runners, and an absent trustlet is an environment limitation
// rather than a defect in this package.
func newTestKey(t *testing.T) bindingKey {
	t.Helper()
	provider := newKeyProvider()
	t.Cleanup(func() {
		if err := provider.deleteKey(testKeyName); err != nil {
			t.Logf("cleaning up the test key: %v", err)
		}
	})
	key, err := provider.getOrCreateKey(testKeyName)
	if err != nil {
		if errors.Is(err, ErrCredentialGuardNotAvailable) {
			t.Skipf("this host cannot create a KeyGuard key: %v", err)
		}
		t.Fatalf("getOrCreateKey: %v", err)
	}
	t.Cleanup(func() { _ = key.Close() })
	return key
}

func TestKeyGuardKeyIsVirtualIsolated(t *testing.T) {
	key := newTestKey(t)
	if key.Type != keyTypeKeyGuard {
		t.Fatalf("key type = %s, want KeyGuard. Virtualization Based Security and Credential Guard must be running for an IMDSv2 binding key.", key.Type)
	}
	if err := requireKeyGuard(key); err != nil {
		t.Errorf("requireKeyGuard rejected a KeyGuard key: %v", err)
	}
	pub, ok := key.Signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want *rsa.PublicKey", key.Signer.Public())
	}
	if got := pub.N.BitLen(); got != csrKeyBits {
		t.Errorf("key size = %d bits, want %d", got, csrKeyBits)
	}
	if pub.E != 65537 {
		t.Errorf("public exponent = %d, want 65537", pub.E)
	}
}

// TestKeyGuardSignPSS proves the trustlet produces a signature that verifies
// against the exported public key, which is what IMDS and the TLS peer do.
func TestKeyGuardSignPSS(t *testing.T) {
	key := newTestKey(t)
	pub := key.Signer.Public().(*rsa.PublicKey)

	digest := sha256.Sum256([]byte("msal-go imdsv2 binding key"))
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	signature, err := key.Signer.Sign(rand.Reader, digest[:], opts)
	if err != nil {
		t.Fatalf("signing with the KeyGuard key: %v", err)
	}
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], signature, opts); err != nil {
		t.Fatalf("the PSS signature did not verify: %v", err)
	}
	// A signature over a different digest must not verify, otherwise the check
	// above would pass for any bytes at all.
	other := sha256.Sum256([]byte("a different message"))
	if err := rsa.VerifyPSS(pub, crypto.SHA256, other[:], signature, opts); err == nil {
		t.Error("a signature verified against the wrong digest")
	}
}

// TestKeyGuardSignPKCS1 covers the padding a TLS 1.2 handshake may select.
func TestKeyGuardSignPKCS1(t *testing.T) {
	key := newTestKey(t)
	pub := key.Signer.Public().(*rsa.PublicKey)

	digest := sha256.Sum256([]byte("pkcs1 v1.5"))
	signature, err := key.Signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("signing with PKCS#1 v1.5: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("the PKCS#1 v1.5 signature did not verify: %v", err)
	}
}

// TestKeyGuardCSR is the end-to-end check for the half of the flow that can run
// without a managed identity: a CSR built and signed entirely inside the
// trustlet must parse and verify.
func TestKeyGuardCSR(t *testing.T) {
	key := newTestKey(t)
	pub := key.Signer.Public().(*rsa.PublicKey)

	csr, err := createCSR(key.Signer, testCSRClientID, testCSRTenantID, cuidInfo{VMID: testCSRVMID})
	if err != nil {
		t.Fatalf("createCSR with a KeyGuard key: %v", err)
	}
	if err := verifyCSRSignature(csr, pub); err != nil {
		t.Fatalf("the KeyGuard-signed CSR did not verify: %v", err)
	}
}

// TestKeyGuardKeyIsStable checks that a second request returns the same key
// rather than replacing it, so a cached certificate keeps matching its key.
func TestKeyGuardKeyIsStable(t *testing.T) {
	first := newTestKey(t)
	firstPub := first.Signer.Public().(*rsa.PublicKey)

	second, err := newKeyProvider().getOrCreateKey(testKeyName)
	if err != nil {
		t.Fatalf("reopening the key: %v", err)
	}
	defer func() { _ = second.Close() }()

	secondPub, ok := second.Signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want *rsa.PublicKey", second.Signer.Public())
	}
	if firstPub.N.Cmp(secondPub.N) != 0 {
		t.Error("reopening the key returned a different key")
	}
	if second.Type != keyTypeKeyGuard {
		t.Errorf("reopened key type = %s, want KeyGuard", second.Type)
	}
}

// TestKeyGuardDeleteKey checks that a key can be discarded, which is how the
// library recovers from a key Entra will no longer accept.
func TestKeyGuardDeleteKey(t *testing.T) {
	provider := newKeyProvider()
	key, err := provider.getOrCreateKey(testKeyName)
	if err != nil {
		if errors.Is(err, ErrCredentialGuardNotAvailable) {
			t.Skipf("this host cannot create a KeyGuard key: %v", err)
		}
		t.Fatalf("getOrCreateKey: %v", err)
	}
	original := key.Signer.Public().(*rsa.PublicKey)
	_ = key.Close()

	if err := provider.deleteKey(testKeyName); err != nil {
		t.Fatalf("deleteKey: %v", err)
	}
	// Deleting a key that is already gone is not an error, so that cleanup after
	// a partial failure stays simple.
	if err := provider.deleteKey(testKeyName); err != nil {
		t.Errorf("deleting an absent key returned %v, want nil", err)
	}

	replacement, err := provider.getOrCreateKey(testKeyName)
	if err != nil {
		t.Fatalf("recreating the key: %v", err)
	}
	defer func() {
		_ = replacement.Close()
		_ = provider.deleteKey(testKeyName)
	}()
	if replacement.Signer.Public().(*rsa.PublicKey).N.Cmp(original.N) == 0 {
		t.Error("recreating the key after deletion returned the original key")
	}
}

// TestSignerRejectsMismatchedDigest guards the length check in Sign.
func TestSignerRejectsMismatchedDigest(t *testing.T) {
	key := newTestKey(t)
	if _, err := key.Signer.Sign(rand.Reader, []byte("too short"), crypto.SHA256); err == nil {
		t.Error("Sign accepted a digest whose length does not match the hash")
	}
}

// TestSignerAfterCloseFails checks that a closed signer cannot be used, so a
// use-after-free reaches Go rather than CNG.
func TestSignerAfterCloseFails(t *testing.T) {
	provider := newKeyProvider()
	key, err := provider.getOrCreateKey(testKeyName)
	if err != nil {
		if errors.Is(err, ErrCredentialGuardNotAvailable) {
			t.Skipf("this host cannot create a KeyGuard key: %v", err)
		}
		t.Fatalf("getOrCreateKey: %v", err)
	}
	defer func() { _ = provider.deleteKey(testKeyName) }()

	if err := key.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := key.Close(); err != nil {
		t.Errorf("closing twice returned %v, want nil", err)
	}
	digest := sha256.Sum256([]byte("after close"))
	if _, err := key.Signer.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Error("signing with a closed key succeeded")
	}
}
