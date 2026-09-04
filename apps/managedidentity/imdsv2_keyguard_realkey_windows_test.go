// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build windows

package managedidentity

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- a certificate store thumbprint is SHA-1 by definition.
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"os"
	"testing"
	"time"
)

// These tests use the real KeyGuard key in the shared CNG container. They need
// a host with VBS running and they mutate machine state, so they are off by
// default; set MSAL_TEST_REAL_KEYGUARD=1 to opt in.
//
// They deliberately do not delete the key afterwards. The container is shared
// with MSAL .NET, and deleting it would invalidate every certificate either
// library has already persisted against it.
const realKeyGuardEnvVar = "MSAL_TEST_REAL_KEYGUARD"

// realKeyGuardPubOut names a file to write the public key to, in the SPKI DER
// form base64 encoded. It is how the cross-language check compares the key Go
// opens with the key MSAL .NET opens from the same container.
const realKeyGuardPubOut = "MSAL_TEST_REAL_KEYGUARD_PUBOUT"

// realKeyGuardCertOut names a file to write the persisted certificate's
// thumbprint to. When it is set the store entry deliberately outlives the test,
// because the MSAL .NET side of the interop check runs afterwards and has to
// find it; that run is what removes the entry again.
const realKeyGuardCertOut = "MSAL_TEST_REAL_KEYGUARD_CERTOUT"

func requireRealKeyGuard(t *testing.T) keyProvider {
	t.Helper()
	if os.Getenv(realKeyGuardEnvVar) != "1" {
		t.Skipf("set %s=1 to run tests against the real KeyGuard key", realKeyGuardEnvVar)
	}
	return newKeyProvider()
}

func rsaPublic(t *testing.T, key bindingKey) *rsa.PublicKey {
	t.Helper()
	pub, ok := key.Signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *rsa.PublicKey", key.Signer.Public())
	}
	return pub
}

// TestRealKeyGuardKeyIsIsolated proves the provider really produces a
// VBS-isolated key on this host, rather than silently falling back to a
// software key that would satisfy every type assertion while offering none of
// the guarantees.
func TestRealKeyGuardKeyIsIsolated(t *testing.T) {
	provider := requireRealKeyGuard(t)

	key, err := provider.getOrCreateKey(bindingKeyName)
	if err != nil {
		t.Fatalf("getOrCreateKey: %v", err)
	}
	defer func() { _ = key.Close() }()

	if key.Type != keyTypeKeyGuard {
		t.Fatalf("key type = %s, want KeyGuard; this host reported VBS but produced a weaker key", key.Type)
	}
	if err := requireKeyGuard(key); err != nil {
		t.Fatalf("requireKeyGuard rejected a key the provider called KeyGuard: %v", err)
	}
	pub := rsaPublic(t, key)
	if pub.N.BitLen() < 2048 {
		t.Errorf("key is %d bits, want at least 2048", pub.N.BitLen())
	}
}

// TestRealKeyGuardKeySigns proves the handle is usable for the operation the
// whole flow depends on: the CSR and the TLS handshake are both signatures made
// by a key whose private half never enters this process.
func TestRealKeyGuardKeySigns(t *testing.T) {
	provider := requireRealKeyGuard(t)

	key, err := provider.getOrCreateKey(bindingKeyName)
	if err != nil {
		t.Fatalf("getOrCreateKey: %v", err)
	}
	defer func() { _ = key.Close() }()

	digest := sha256.Sum256([]byte("msal-go keyguard signing proof"))

	pkcs1, err := key.Signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("PKCS#1 v1.5 sign: %v", err)
	}
	pub := rsaPublic(t, key)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], pkcs1); err != nil {
		t.Fatalf("the isolated key produced a PKCS#1 signature that does not verify: %v", err)
	}

	// TLS 1.3 requires PSS, so the same handle has to serve both schemes.
	pssOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	pss, err := key.Signer.Sign(rand.Reader, digest[:], pssOpts)
	if err != nil {
		t.Fatalf("PSS sign: %v", err)
	}
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], pss, pssOpts); err != nil {
		t.Fatalf("the isolated key produced a PSS signature that does not verify: %v", err)
	}
}

// TestRealKeyGuardPersistedCertificateIsUsable is the end-to-end shared-state
// proof: a certificate persisted by msal-go, bound to the shared container,
// must be recoverable from the operating system store and pairable with the
// isolated key. MSAL .NET reads the same store and the same container, so this
// is the state the two libraries hand each other.
//
// It writes under an alias scoped to the run and removes it again, so it never
// disturbs a certificate a real acquisition persisted.
func TestRealKeyGuardPersistedCertificateIsUsable(t *testing.T) {
	provider := requireRealKeyGuard(t)
	if os.Getenv(realStoreEnvVar) != "1" {
		t.Skipf("set %s=1 as well; this test writes to the certificate store", realStoreEnvVar)
	}
	store := windowsPersistentCertCache{}

	// When the entry is being published for the .NET interop check it has to
	// outlive this test, so cleanup is left to that run. Otherwise it is
	// removed here like any other scoped alias.
	publishTo := os.Getenv(realKeyGuardCertOut)
	alias := uniqueAlias(t)
	if publishTo == "" {
		alias = scopedAlias(t, store)
	} else {
		t.Logf("alias %s is left in the store for the .NET interop check to consume and remove", alias)
	}

	key, err := provider.getOrCreateKey(bindingKeyName)
	if err != nil {
		t.Fatalf("getOrCreateKey: %v", err)
	}
	defer func() { _ = key.Close() }()
	pub := rsaPublic(t, key)

	const (
		clientID = "8c8a1b0a-4d40-4d9e-9a4f-1f2a3b4c5d6e"
		tenantID = "72f988bf-86f1-41af-91ab-2d7cd011db47"
		endpoint = "https://169.254.169.254/metadata/identity/oauth2/token"
	)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: clientID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
	}
	// Signed by the isolated key itself, so the certificate can only exist if
	// the trustlet performed the signature.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key.Signer)
	if err != nil {
		t.Fatalf("create certificate with the isolated key: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	store.write(alias, &bindingCertificate{
		TLS:      tls.Certificate{Certificate: [][]byte{der}, Leaf: leaf},
		Leaf:     leaf,
		ClientID: clientID,
		TenantID: tenantID,
		Endpoint: endpoint,
	})

	got, ok := store.read(alias)
	if !ok {
		t.Fatal("the certificate did not come back from the store")
	}
	gotPub, ok := got.Leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("restored certificate carries a %T public key", got.Leaf.PublicKey)
	}
	if !gotPub.Equal(pub) {
		t.Fatal("the restored certificate does not match the isolated key; pairing would fail")
	}
	// CheckSignatureFrom would additionally demand CA constraints, which a
	// binding certificate deliberately does not carry. What matters here is
	// only that the isolated key produced the signature.
	if err := got.Leaf.CheckSignature(got.Leaf.SignatureAlgorithm, got.Leaf.RawTBSCertificate, got.Leaf.Signature); err != nil {
		t.Fatalf("the restored certificate's signature does not verify against the isolated key: %v", err)
	}

	// Hand the thumbprint to the .NET side of the interop check.
	if publishTo != "" {
		sum := sha1.Sum(got.DER) // #nosec G401 -- a store thumbprint is SHA-1 by definition.
		if err := os.WriteFile(publishTo, []byte(hex.EncodeToString(sum[:])), 0o600); err != nil {
			t.Fatalf("write %s: %v", publishTo, err)
		}
	}
}

// on: opening the named container twice yields the same key, so a second opener
// adopts the existing key instead of overwriting it.
//
// This is what makes it safe for MSAL .NET and msal-go to name the same
// container. If the second open created a new key, whichever library ran second
// would silently invalidate every certificate the first had persisted.
func TestRealKeyGuardContainerIsStable(t *testing.T) {
	provider := requireRealKeyGuard(t)

	first, err := provider.getOrCreateKey(bindingKeyName)
	if err != nil {
		t.Fatalf("first getOrCreateKey: %v", err)
	}
	defer func() { _ = first.Close() }()
	firstPub := rsaPublic(t, first)

	second, err := provider.getOrCreateKey(bindingKeyName)
	if err != nil {
		t.Fatalf("second getOrCreateKey: %v", err)
	}
	defer func() { _ = second.Close() }()
	secondPub := rsaPublic(t, second)

	if !firstPub.Equal(secondPub) {
		t.Fatal("opening the container twice produced different keys; a second library opening it would orphan the first's certificates")
	}
	if second.Type != keyTypeKeyGuard {
		t.Errorf("second open reported type %s, want KeyGuard", second.Type)
	}

	// Publish the public key so the MSAL .NET side of the interop check can be
	// compared against exactly this key.
	if path := os.Getenv(realKeyGuardPubOut); path != "" {
		der, err := x509.MarshalPKIXPublicKey(firstPub)
		if err != nil {
			t.Fatalf("marshal public key: %v", err)
		}
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(der)), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}
