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
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
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
	// The size is an interoperability invariant, not a floor: MSAL .NET creates
	// this same container at 2048 bits, and createCSR refuses anything else.
	if pub.N.BitLen() != csrKeyBits {
		t.Errorf("key is %d bits, want exactly %d to match the key MSAL .NET creates in this container",
			pub.N.BitLen(), csrKeyBits)
	}
}

// realKeyGuardRaceChildEnvVar makes a test binary act as one racer in
// TestRealKeyGuardCrossProcessCreationConverges rather than as the parent. Its
// value is the container name to provision.
const realKeyGuardRaceChildEnvVar = "MSAL_TEST_KEYGUARD_RACE_CONTAINER"

// TestRealKeyGuardCrossProcessCreationConverges races real, separate processes
// for one container.
//
// This is the only test here that can reach the race that matters. bindingKeyGate
// serializes goroutines inside one process, so an in-process test can never have
// two callers inside their create-finalize sequence at once - which is precisely
// the window in which NCryptCreatePersistedKey succeeds for both and the later
// NCryptFinalizeKey silently replaces the earlier. Separate processes share
// nothing but the container and the named mutex, so they can.
//
// The assertion is convergence: however the race resolves, every process must
// end up reporting the same public key, and the key persisted afterwards must be
// that one. That holds whether the named mutex serialized them - the intended
// path - or the mutex was unavailable and the persisted-winner check in
// resolveBindingKey caught a silent replace. A process that adopted a stranded
// key would report a modulus nobody else saw and fail here.
//
// It runs on a throwaway container, never the shared bindingKeyName, and deletes
// it afterwards.
func TestRealKeyGuardCrossProcessCreationConverges(t *testing.T) {
	if container := os.Getenv(realKeyGuardRaceChildEnvVar); container != "" {
		runKeyGuardRaceChild(t, container)
		return
	}
	provider := requireRealKeyGuard(t)

	name := fmt.Sprintf("msalgo-xproc-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = provider.deleteKey(name) })
	if _, err := provider.openKey(name); !errors.Is(err, errBindingKeyNotFound) {
		t.Fatalf("the throwaway container already exists: %v", err)
	}

	const racers = 4
	type result struct {
		out string
		err error
	}
	results := make(chan result, racers)
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// #nosec G204 -- the command is this test binary and the arguments
			// are constants; nothing here comes from outside the test.
			cmd := exec.Command(os.Args[0],
				"-test.run=^TestRealKeyGuardCrossProcessCreationConverges$",
				"-test.v")
			cmd.Env = append(os.Environ(),
				realKeyGuardEnvVar+"=1",
				realKeyGuardRaceChildEnvVar+"="+name,
			)
			out, err := cmd.CombinedOutput()
			results <- result{out: string(out), err: err}
		}()
	}
	wg.Wait()
	close(results)

	moduli := map[string]int{}
	for r := range results {
		if r.err != nil {
			t.Fatalf("a racer failed: %v\n%s", r.err, r.out)
		}
		mod := keyGuardRaceModulus(r.out)
		if mod == "" {
			t.Fatalf("a racer reported no modulus:\n%s", r.out)
		}
		moduli[mod]++
	}
	if len(moduli) != 1 {
		t.Fatalf("racers ended up on %d different keys, want 1: a creator adopted a key that was replaced (%v)", len(moduli), moduli)
	}

	// The key everyone reported must be the one actually persisted, not one
	// that was replaced after the last racer looked.
	final, err := provider.openKey(name)
	if err != nil {
		t.Fatalf("openKey after the race: %v", err)
	}
	defer func() { _ = final.Close() }()
	var agreed string
	for mod := range moduli {
		agreed = mod
	}
	if got := rsaPublic(t, final).N.Text(16); got != agreed {
		t.Fatalf("the persisted key is %s but every racer reported %s", got, agreed)
	}
}

// runKeyGuardRaceChild is the child half: provision the container and print the
// public modulus for the parent to compare.
func runKeyGuardRaceChild(t *testing.T, container string) {
	t.Helper()
	provider := requireRealKeyGuard(t)
	key, err := provider.getOrCreateKey(container)
	if err != nil {
		t.Fatalf("getOrCreateKey: %v", err)
	}
	defer func() { _ = key.Close() }()
	fmt.Printf("%s%s\n", keyGuardRaceModulusPrefix, rsaPublic(t, key).N.Text(16))
}

const keyGuardRaceModulusPrefix = "KEYGUARD_RACE_MODULUS="

func keyGuardRaceModulus(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, keyGuardRaceModulusPrefix) {
			return strings.TrimPrefix(line, keyGuardRaceModulusPrefix)
		}
	}
	return ""
}

// TestRealKeyGuardConcurrentCreationConvergesOnOneKey checks that concurrent
// callers in one process end up bound to a single real VBS key.
//
// Be clear about what this does and does not prove. bindingKeyGate serializes
// these goroutines before any of them reaches the container, so exactly one
// takes the create branch and the rest open what it made. Neither the NTE_EXISTS
// branch nor the silent-replace branch is exercised here, and neither can be
// from one process. Those are covered deterministically through the
// bindingKeyContainer seam - see
// TestResolveBindingKeyAdoptsThePersistedWinnerAfterASilentReplace - and against
// real processes by TestRealKeyGuardCrossProcessCreationConverges above.
//
// What this test does prove, against real CNG rather than a script: that the
// serialized callers converge on one key rather than each replacing the last,
// that a second call adopts the existing key instead of creating a new one, and
// that the open-only path sees the same key. Those are the properties that break
// first if NCRYPT_OVERWRITE_KEY_FLAG is reintroduced.
//
// It uses a container of its own rather than the shared one, so the create path
// runs at all: against bindingKeyName the key almost always already exists. The
// throwaway container is deleted afterwards; the shared one never is, because
// MSAL .NET has certificates persisted against it.
func TestRealKeyGuardConcurrentCreationConvergesOnOneKey(t *testing.T) {
	provider := requireRealKeyGuard(t)

	name := fmt.Sprintf("msalgo-race-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = provider.deleteKey(name) })

	// Nothing has created it yet, so the first caller through the gate creates
	// and the rest must adopt what it made.
	if _, err := provider.openKey(name); !errors.Is(err, errBindingKeyNotFound) {
		t.Fatalf("the throwaway container already exists: %v", err)
	}

	const callers = 8
	var wg sync.WaitGroup
	pubs := make([]*rsa.PublicKey, callers)
	errs := make([]error, callers)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			key, err := provider.getOrCreateKey(name)
			if err != nil {
				errs[i] = err
				return
			}
			defer func() { _ = key.Close() }()
			pub, ok := key.Signer.Public().(*rsa.PublicKey)
			if !ok {
				errs[i] = fmt.Errorf("public key is %T", key.Signer.Public())
				return
			}
			pubs[i] = pub
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	for i := 1; i < callers; i++ {
		if pubs[i].N.Cmp(pubs[0].N) != 0 {
			t.Fatalf("caller %d got a different key from caller 0: concurrent creation replaced a key instead of adopting it", i)
		}
	}

	// A key that exists is reopened, not recreated, so an open-only caller sees
	// the same one.
	opened, err := provider.openKey(name)
	if err != nil {
		t.Fatalf("openKey after concurrent creation: %v", err)
	}
	defer func() { _ = opened.Close() }()
	if rsaPublic(t, opened).N.Cmp(pubs[0].N) != 0 {
		t.Fatal("openKey returned a different key from the one getOrCreateKey settled on")
	}

	// And a later getOrCreateKey adopts that key rather than making another,
	// which is the property NCRYPT_OVERWRITE_KEY_FLAG would destroy: with the
	// flag restored this call would replace a key the handles above still name.
	again, err := provider.getOrCreateKey(name)
	if err != nil {
		t.Fatalf("getOrCreateKey on an existing key: %v", err)
	}
	defer func() { _ = again.Close() }()
	if rsaPublic(t, again).N.Cmp(pubs[0].N) != 0 {
		t.Fatal("getOrCreateKey replaced an existing usable key instead of adopting it")
	}
}

// TestRealKeyGuardStaleHandleDeleteDestroysTheReplacement encodes, against the
// real KSP, the behaviour that makes deleting through a stale handle unsafe.
//
// NCryptDeleteKey resolves the *name*, not the object the handle was opened
// from. So a process that opened the key, lost the race, and then "cleaned up"
// its stale handle destroys whatever now holds the name - and is told it
// succeeded. This was observed 3/3 by hand on a development machine; this test
// makes it a standing fact rather than an anecdote, so that anyone who
// reintroduces delete-on-stale sees exactly what it costs.
//
// It runs on a throwaway container and never touches bindingKeyName.
func TestRealKeyGuardStaleHandleDeleteDestroysTheReplacement(t *testing.T) {
	requireRealKeyGuard(t)

	name := fmt.Sprintf("msalgo-stale-%d", time.Now().UnixNano())
	keyName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := openProvider()
	if err != nil {
		t.Fatalf("openProvider: %v", err)
	}
	defer freeNCryptObject(provider)
	t.Cleanup(func() { _ = newKeyProvider().deleteKey(name) })

	// A: the key this process opened and is still holding.
	stale, err := createPersistedKey(provider, keyName, false)
	if err != nil {
		t.Fatalf("creating the first key: %v", err)
	}
	staledPub, err := exportRSAPublic(stale)
	if err != nil {
		t.Fatalf("exporting the first public key: %v", err)
	}

	// B: another party replaces the name, exactly as recovery now does.
	replacement, err := createPersistedKey(provider, keyName, true)
	if err != nil {
		freeNCryptObject(stale)
		t.Fatalf("replacing the key: %v", err)
	}
	replacementPub, err := exportRSAPublic(replacement)
	if err != nil {
		t.Fatalf("exporting the replacement public key: %v", err)
	}
	freeNCryptObject(replacement)

	if staledPub.N.Cmp(replacementPub.N) == 0 {
		t.Fatal("the replacement reused the same key, so this test proves nothing")
	}
	// The name resolves to B before the delete.
	before, existed, err := openExistingKey(provider, keyName)
	if err != nil || !existed {
		t.Fatalf("the name did not resolve to the replacement (existed=%t err=%v)", existed, err)
	}
	beforePub, err := exportRSAPublic(before)
	freeNCryptObject(before)
	if err != nil {
		t.Fatalf("exporting the persisted public key: %v", err)
	}
	if beforePub.N.Cmp(replacementPub.N) != 0 {
		t.Fatal("the name did not resolve to the replacement before the delete")
	}

	// Deleting through the STALE handle. This is the operation the recovery
	// path must never perform.
	if err := deleteKeyHandle(stale); err != nil {
		t.Fatalf("deleting through the stale handle: %v", err)
	}

	after, stillThere, err := openExistingKey(provider, keyName)
	if err != nil {
		t.Fatalf("reopening after the delete: %v", err)
	}
	if stillThere {
		freeNCryptObject(after)
		t.Skip("this KSP kept the replacement after a stale-handle delete; the hazard this guards against does not reproduce here")
	}
	// The replacement is gone. That is the whole point: a stale-handle delete
	// destroyed a key this process never created and had no right to remove.
	t.Log("confirmed: deleting through a stale handle removed the replacement under the same name")
}

// TestRealKeyGuardRecoversStaleKeyByOverwriting drives the recovery path against
// the real KSP.
//
// A real key cannot be made unsignable on demand, so the usability answer is
// scripted for exactly one probe while every other operation is the real NCrypt
// one. That is enough to reach the branch under test: the loop sees a key it
// believes is dead, must release the handle rather than delete through it, and
// must recreate over the name with overwrite - which only succeeds because the
// replacement flags carry NCRYPT_OVERWRITE_KEY_FLAG.
//
// Afterwards the name must still resolve, and to the key that was adopted.
func TestRealKeyGuardRecoversStaleKeyByOverwriting(t *testing.T) {
	requireRealKeyGuard(t)

	name := fmt.Sprintf("msalgo-recover-%d", time.Now().UnixNano())
	keyName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := openProvider()
	if err != nil {
		t.Fatalf("openProvider: %v", err)
	}
	defer freeNCryptObject(provider)
	t.Cleanup(func() { _ = newKeyProvider().deleteKey(name) })

	// Seed the container so the loop finds an existing key to call stale.
	seeded, err := createPersistedKey(provider, keyName, false)
	if err != nil {
		t.Fatalf("seeding the container: %v", err)
	}
	seededPub, err := exportRSAPublic(seeded)
	if err != nil {
		t.Fatalf("exporting the seeded public key: %v", err)
	}
	freeNCryptObject(seeded)

	c := &staleUntilReplacedContainer{inner: cngBindingKeyContainer{provider: provider, name: keyName}}
	key, err := resolveBindingKey(c, name)
	if err != nil {
		t.Fatalf("resolveBindingKey: %v", err)
	}
	defer func() { _ = key.Close() }()

	// Both probes - the initial one and the reopen that guards against
	// overwriting somebody's replacement - must have run and reported dead,
	// otherwise the overwrite branch was never reached.
	if c.probes < 2 {
		t.Fatalf("the usability probe ran %d times, want at least 2: the recovery path was not exercised", c.probes)
	}
	if !c.overwrote {
		t.Fatal("recovery created without overwrite, which cannot replace an existing name")
	}
	adoptedPub, ok := key.Signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T", key.Signer.Public())
	}
	if adoptedPub.N.Cmp(seededPub.N) == 0 {
		t.Fatal("recovery adopted the key it had just declared stale")
	}
	// The name still resolves, and to the adopted key: recovery replaced it
	// rather than deleting it and leaving the container empty.
	persisted, existed, err := openExistingKey(provider, keyName)
	if err != nil {
		t.Fatalf("reopening after recovery: %v", err)
	}
	if !existed {
		t.Fatal("recovery left the container empty: the stale key was deleted rather than replaced")
	}
	defer freeNCryptObject(persisted)
	persistedPub, err := exportRSAPublic(persisted)
	if err != nil {
		t.Fatalf("exporting the persisted public key: %v", err)
	}
	if persistedPub.N.Cmp(adoptedPub.N) != 0 {
		t.Fatal("the persisted key is not the one recovery adopted")
	}
}

// staleUntilReplacedContainer reports the persisted key as dead until it has
// been recreated, and defers every other operation to the real CNG container.
//
// A real key cannot be made unsignable on demand, so this is how the recovery
// branch is reached against real NCrypt. Reporting dead until the create means
// both the initial probe and the reopen guard see a dead key, which is what a
// genuinely reaped per-boot key looks like.
type staleUntilReplacedContainer struct {
	inner     cngBindingKeyContainer
	probes    int
	created   bool
	overwrote bool
}

func (s *staleUntilReplacedContainer) open() (windows.Handle, bool, error) { return s.inner.open() }

func (s *staleUntilReplacedContainer) usable(h windows.Handle) bool {
	if !s.created {
		s.probes++
		return false
	}
	return s.inner.usable(h)
}

func (s *staleUntilReplacedContainer) create(overwrite bool) (windows.Handle, error) {
	s.overwrote = overwrite
	h, err := s.inner.create(overwrite)
	if err == nil {
		s.created = true
	}
	return h, err
}

func (s *staleUntilReplacedContainer) persisted(candidate windows.Handle) (bool, error) {
	return s.inner.persisted(candidate)
}

func (s *staleUntilReplacedContainer) discard(h windows.Handle) { s.inner.discard(h) }

func (s *staleUntilReplacedContainer) adopt(h windows.Handle) (bindingKey, error) {
	return s.inner.adopt(h)
}

// TestRealKeyGuardSignHonoursPSSSaltSentinels proves against real CNG that the
// two PSS sentinels produce different signatures, and that each verifies at the
// exact salt length it promised.
//
// Verification is done with an exact salt rather than PSSSaltLengthAuto, because
// crypto/rsa's Auto verification accepts any salt and would pass even if the
// signer had collapsed the sentinels - which is precisely the bug.
func TestRealKeyGuardSignHonoursPSSSaltSentinels(t *testing.T) {
	provider := requireRealKeyGuard(t)

	key, err := provider.getOrCreateKey(bindingKeyName)
	if err != nil {
		t.Fatalf("getOrCreateKey: %v", err)
	}
	defer func() { _ = key.Close() }()

	pub := rsaPublic(t, key)
	digest := sha256.Sum256([]byte("pss salt sentinels"))
	maxSalt := (pub.N.BitLen()-1+7)/8 - sha256.Size - 2

	autoSig, err := key.Signer.Sign(rand.Reader, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("signing with PSSSaltLengthAuto: %v", err)
	}
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], autoSig, &rsa.PSSOptions{
		SaltLength: maxSalt, Hash: crypto.SHA256,
	}); err != nil {
		t.Fatalf("the Auto signature does not verify at the maximum salt %d: %v", maxSalt, err)
	}

	hashSig, err := key.Signer.Sign(rand.Reader, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("signing with PSSSaltLengthEqualsHash: %v", err)
	}
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], hashSig, &rsa.PSSOptions{
		SaltLength: sha256.Size, Hash: crypto.SHA256,
	}); err != nil {
		t.Fatalf("the EqualsHash signature does not verify at salt %d: %v", sha256.Size, err)
	}

	// The two must be genuinely different lengths, or the sentinels were
	// collapsed: an Auto signature would then verify at the hash length too.
	if maxSalt == sha256.Size {
		t.Skip("this modulus makes the maximum salt equal the hash size, so the two cannot be told apart")
	}
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], autoSig, &rsa.PSSOptions{
		SaltLength: sha256.Size, Hash: crypto.SHA256,
	}); err == nil {
		t.Fatal("the Auto signature verified at the hash-length salt, so Auto was treated as EqualsHash")
	}
}

// TestRealKeyGuardOpenKeyDoesNotCreate proves the open-only path really is
// open-only: asked for a container that does not exist, it reports that rather
// than provisioning one.
func TestRealKeyGuardOpenKeyDoesNotCreate(t *testing.T) {
	provider := requireRealKeyGuard(t)

	// A name nothing else uses, so a failure here cannot be a key some other
	// library left behind.
	name := fmt.Sprintf("msalgo-openonly-%d", time.Now().UnixNano())
	if _, err := provider.openKey(name); !errors.Is(err, errBindingKeyNotFound) {
		// Clean up in the impossible case that it did create one.
		_ = provider.deleteKey(name)
		t.Fatalf("openKey(%q) = %v, want errBindingKeyNotFound", name, err)
	}
	// If openKey had created the container, a second open would now succeed.
	if _, err := provider.openKey(name); !errors.Is(err, errBindingKeyNotFound) {
		_ = provider.deleteKey(name)
		t.Fatalf("openKey provisioned a key as a side effect of being asked about one: %v", err)
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
