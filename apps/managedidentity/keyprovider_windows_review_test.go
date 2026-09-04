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
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// ---------------------------------------------------------------------------
// The open-create-adopt loop, driven directly.
// ---------------------------------------------------------------------------

// scriptedContainer drives resolveBindingKey without CNG.
//
// It exists because the two branches that matter most cannot be reached through
// getOrCreateKey: that function takes bindingKeyGate first, so goroutines in
// this process are serialized and only one ever reaches the create, and nothing
// a test can do makes real CNG answer NTE_EXISTS on cue. Scripting the container
// reaches them deterministically, below the mutex, over the same loop production
// runs.
type scriptedContainer struct {
	// exists is what open reports, consulted afresh on each call so a script
	// can model another process creating, replacing or deleting the key
	// mid-loop.
	exists   func(opens int) (windows.Handle, bool, error)
	canSign  func(windows.Handle) bool
	createFn func(creates int, overwrite bool) (windows.Handle, error)
	// persistedFn reports whether the candidate is the key the name resolves
	// to. Left nil it answers yes, which is the uncontended case.
	persistedFn func(creates int, candidate windows.Handle) (bool, error)

	opens      int
	creates    int
	opened     []windows.Handle
	adopted    []windows.Handle
	discarded  []windows.Handle
	verified   []windows.Handle
	overwrites []bool
}

func (s *scriptedContainer) open() (windows.Handle, bool, error) {
	h, ok, err := s.exists(s.opens)
	s.opens++
	if err != nil {
		return 0, false, err
	}
	if ok {
		s.opened = append(s.opened, h)
	}
	return h, ok, nil
}

func (s *scriptedContainer) usable(h windows.Handle) bool {
	if s.canSign == nil {
		return true
	}
	return s.canSign(h)
}

func (s *scriptedContainer) create(overwrite bool) (windows.Handle, error) {
	s.overwrites = append(s.overwrites, overwrite)
	h, err := s.createFn(s.creates, overwrite)
	s.creates++
	return h, err
}

func (s *scriptedContainer) persisted(candidate windows.Handle) (bool, error) {
	s.verified = append(s.verified, candidate)
	if s.persistedFn == nil {
		return true, nil
	}
	// creates has already been incremented by create, so the index names the
	// create this verification belongs to.
	return s.persistedFn(s.creates-1, candidate)
}

func (s *scriptedContainer) discard(h windows.Handle) {
	s.discarded = append(s.discarded, h)
}

func (s *scriptedContainer) adopt(h windows.Handle) (bindingKey, error) {
	s.adopted = append(s.adopted, h)
	return bindingKey{Type: keyTypeKeyGuard, Close: func() error { return nil }}, nil
}

// An existing, usable key is adopted as it stands. Creating over it would
// destroy a key other processes and MSAL .NET may already hold certificates
// against.
func TestResolveBindingKeyAdoptsAnExistingUsableKey(t *testing.T) {
	c := &scriptedContainer{
		exists: func(int) (windows.Handle, bool, error) { return 41, true, nil },
		createFn: func(int, bool) (windows.Handle, error) {
			t.Fatal("created a key when a usable one existed")
			return 0, nil
		},
	}
	if _, err := resolveBindingKey(c, bindingKeyName); err != nil {
		t.Fatalf("resolveBindingKey: %v", err)
	}
	if c.creates != 0 {
		t.Errorf("create was called %d times, want 0", c.creates)
	}
	if len(c.discarded) != 0 {
		t.Errorf("an existing usable key's handle was released: %v", c.discarded)
	}
	if len(c.adopted) != 1 || c.adopted[0] != 41 {
		t.Errorf("adopted %v, want the existing key 41", c.adopted)
	}
}

// This is the loser branch, and the reason overwrite was removed. Another
// process creates the key between this call's open and its create; the create
// then fails with NTE_EXISTS, and the only correct response is to go round,
// reopen, and adopt the winner's key. Overwriting instead would replace a key
// the winner is already using.
//
// The test fails if adoption is removed: without the retry pass the create error
// surfaces, and without adopting the reopened key the wrong handle is returned.
func TestResolveBindingKeyAdoptsTheWinnerAfterLosingTheCreate(t *testing.T) {
	const winner windows.Handle = 77
	c := &scriptedContainer{
		// Absent on the first look; present from the moment the rival created
		// it, which is what this call is about to discover.
		exists: func(pass int) (windows.Handle, bool, error) {
			if pass == 0 {
				return 0, false, nil
			}
			return winner, true, nil
		},
		createFn: func(int, bool) (windows.Handle, error) { return 0, errBindingKeyExists },
	}

	key, err := resolveBindingKey(c, bindingKeyName)
	if err != nil {
		t.Fatalf("resolveBindingKey: %v, want the winner's key to be adopted", err)
	}
	if key.Type != keyTypeKeyGuard {
		t.Errorf("key type = %s, want the adopted key", key.Type)
	}
	if c.creates != 1 {
		t.Errorf("create was called %d times, want 1: losing once should not be retried blindly", c.creates)
	}
	if len(c.adopted) != 1 || c.adopted[0] != winner {
		t.Errorf("adopted %v, want the winner's key %d", c.adopted, winner)
	}
	// The key was found on the second pass, not the first: the loop really did
	// go round after losing rather than adopting something it already held.
	if len(c.opened) != 1 || c.opened[0] != winner {
		t.Errorf("opened %v, want exactly one reopen of the winner's key %d", c.opened, winner)
	}
	if len(c.overwrites) != 0 && c.overwrites[len(c.overwrites)-1] {
		t.Error("the winner's key was overwritten instead of adopted")
	}
}

// A key that opens but can no longer sign is what a reboot leaves behind. It is
// released and recreated over, never deleted through.
//
// The distinction is the whole fix. NCryptDeleteKey resolves the name rather
// than the handle's object, so deleting through a stale handle destroys whatever
// now holds the name - reproduced 3/3 against the Microsoft Software KSP: open
// A, replace the name with B, delete through A, B is gone, success reported.
// This test fails if that behaviour comes back, because a delete would show up
// on the container.
func TestResolveBindingKeyRecoversAStaleKeyWithoutDeletingIt(t *testing.T) {
	const stale windows.Handle = 9
	const fresh windows.Handle = 10
	c := &scriptedContainer{}
	c.exists = func(int) (windows.Handle, bool, error) { return stale, true, nil }
	c.canSign = func(h windows.Handle) bool { return h != stale }
	c.createFn = func(int, bool) (windows.Handle, error) { return fresh, nil }

	if _, err := resolveBindingKey(c, bindingKeyName); err != nil {
		t.Fatalf("resolveBindingKey: %v", err)
	}
	// Two stale handles are observed on this script - the initial open and the
	// reopen that guards against overwriting a replacement - and BOTH must be
	// released rather than deleted through. Counting them is what catches a
	// reintroduced delete: a delete consumes the handle without going through
	// the container, so the count drops.
	if len(c.discarded) != 2 {
		t.Fatalf("released %d stale handles, want 2: a handle was deleted through instead of freed", len(c.discarded))
	}
	for _, h := range c.discarded {
		if h != stale {
			t.Errorf("discarded %#x, want only the stale handle %#x", h, stale)
		}
	}
	if c.creates != 1 {
		t.Fatalf("create was called %d times, want 1", c.creates)
	}
	// Recreating over a name that still exists requires overwrite; without it
	// the create can only ever return NTE_EXISTS.
	if len(c.overwrites) != 1 || !c.overwrites[0] {
		t.Fatalf("create overwrite flags = %v, want a single overwriting create", c.overwrites)
	}
	if len(c.adopted) != 1 || c.adopted[0] != fresh {
		t.Errorf("adopted %v, want the replacement key %#x", c.adopted, fresh)
	}
}

// The window between deciding a key is unusable and replacing it is a race, and
// the good outcome is to adopt somebody else's replacement rather than overwrite
// it. This scripts exactly that: the first open reports the dead key, and by the
// second open another process has put a working one under the name.
//
// It fails if the reopen is removed, because the loop would then overwrite a
// live key and `overwrites` would show a create that should never have happened.
func TestResolveBindingKeyAdoptsAReplacementRacedInDuringRecovery(t *testing.T) {
	const stale windows.Handle = 0x21
	const rival windows.Handle = 0x22
	c := &scriptedContainer{}
	c.exists = func(opens int) (windows.Handle, bool, error) {
		if opens == 0 {
			return stale, true, nil
		}
		return rival, true, nil
	}
	c.canSign = func(h windows.Handle) bool { return h != stale }
	c.createFn = func(int, bool) (windows.Handle, error) {
		t.Fatal("overwrote a key another process had already replaced")
		return 0, nil
	}

	if _, err := resolveBindingKey(c, bindingKeyName); err != nil {
		t.Fatalf("resolveBindingKey: %v", err)
	}
	if c.creates != 0 {
		t.Errorf("create was called %d times, want 0: the replacement should have been adopted", c.creates)
	}
	if len(c.adopted) != 1 || c.adopted[0] != rival {
		t.Errorf("adopted %v, want the rival's replacement %#x", c.adopted, rival)
	}
	if len(c.discarded) != 1 || c.discarded[0] != stale {
		t.Errorf("discarded %v, want only the stale handle released", c.discarded)
	}
}

// A stale key that another process deleted outright leaves the name free, so an
// ordinary non-overwriting create is both sufficient and safer than forcing one.
func TestResolveBindingKeyCreatesWithoutOverwriteWhenTheStaleNameVanishes(t *testing.T) {
	const stale windows.Handle = 0x31
	const fresh windows.Handle = 0x32
	c := &scriptedContainer{}
	c.exists = func(opens int) (windows.Handle, bool, error) {
		if opens == 0 {
			return stale, true, nil
		}
		return 0, false, nil
	}
	c.canSign = func(h windows.Handle) bool { return h != stale }
	c.createFn = func(int, bool) (windows.Handle, error) { return fresh, nil }

	if _, err := resolveBindingKey(c, bindingKeyName); err != nil {
		t.Fatalf("resolveBindingKey: %v", err)
	}
	if len(c.overwrites) != 1 || c.overwrites[0] {
		t.Fatalf("create overwrite flags = %v, want a single non-overwriting create", c.overwrites)
	}
	if len(c.adopted) != 1 || c.adopted[0] != fresh {
		t.Errorf("adopted %v, want the new key %#x", c.adopted, fresh)
	}
}

// An ordinary create - the name was free - must never ask for overwrite, or a
// racing creator's key would be destroyed instead of adopted.
func TestResolveBindingKeyDoesNotOverwriteWhenTheNameWasFree(t *testing.T) {
	const fresh windows.Handle = 0x41
	c := &scriptedContainer{
		exists:   func(int) (windows.Handle, bool, error) { return 0, false, nil },
		createFn: func(int, bool) (windows.Handle, error) { return fresh, nil },
	}
	if _, err := resolveBindingKey(c, bindingKeyName); err != nil {
		t.Fatalf("resolveBindingKey: %v", err)
	}
	if len(c.overwrites) != 1 || c.overwrites[0] {
		t.Fatalf("create overwrite flags = %v, want a single non-overwriting create", c.overwrites)
	}
}

// The replacement flag set has to be what MSAL .NET's CreateFresh uses:
// overwrite plus virtual isolation plus per-boot. Dropping isolation or the
// per-boot flag would produce a key IMDS refuses a credential for.
func TestBindingKeyReplaceFlagsMatchDotNetCreateFresh(t *testing.T) {
	if bindingKeyReplaceFlags&ncryptOverwriteKeyFlag == 0 {
		t.Error("the replacement flags do not overwrite, so recovery can only ever return NTE_EXISTS")
	}
	if bindingKeyReplaceFlags&ncryptUseVirtualIsolationFlag == 0 {
		t.Error("the replacement flags no longer ask for VBS isolation")
	}
	if bindingKeyReplaceFlags&ncryptUsePerBootKeyFlag == 0 {
		t.Error("the replacement flags no longer ask for a per-boot key, which IMDS requires")
	}
	if bindingKeyReplaceFlags != bindingKeyCreateFlags|ncryptOverwriteKeyFlag {
		t.Error("the replacement flags differ from the create flags by something other than overwrite")
	}
}

// Losing the create forever is pathological - it needs a rival that creates the
// key and then deletes it again on every pass - so the loop is bounded and ends
// in a named error rather than spinning against a rate-limited machine.
func TestResolveBindingKeyGivesUpAfterBoundedAttempts(t *testing.T) {
	c := &scriptedContainer{
		// Never there when looked for, always there when created against: the
		// rival wins every race and then withdraws.
		exists:   func(int) (windows.Handle, bool, error) { return 0, false, nil },
		createFn: func(int, bool) (windows.Handle, error) { return 0, errBindingKeyExists },
	}

	_, err := resolveBindingKey(c, bindingKeyName)
	if err == nil {
		t.Fatal("resolveBindingKey looped forever or reported success")
	}
	if !errors.Is(err, ErrCredentialGuardNotAvailable) {
		t.Errorf("error = %v, want it to wrap ErrCredentialGuardNotAvailable", err)
	}
	if !strings.Contains(err.Error(), bindingKeyName) {
		t.Errorf("error = %v, want it to name the container", err)
	}
	if c.creates != bindingKeyCreateAttempts {
		t.Errorf("create was called %d times, want exactly %d", c.creates, bindingKeyCreateAttempts)
	}
	if len(c.adopted) != 0 {
		t.Errorf("a key was adopted on a path that failed: %v", c.adopted)
	}
}

// A create failure that is not the lost race is the host refusing to make the
// key at all, and must surface immediately rather than being retried.
func TestResolveBindingKeyDoesNotRetryARealCreateFailure(t *testing.T) {
	sentinel := fmt.Errorf("%w: no VBS here", ErrCredentialGuardNotAvailable)
	c := &scriptedContainer{
		exists:   func(int) (windows.Handle, bool, error) { return 0, false, nil },
		createFn: func(int, bool) (windows.Handle, error) { return 0, sentinel },
	}
	_, err := resolveBindingKey(c, bindingKeyName)
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want the create failure surfaced verbatim", err)
	}
	if c.creates != 1 {
		t.Errorf("create was called %d times, want 1: a real failure must not be retried", c.creates)
	}
}

// The production provider drives the same loop through the real NCrypt calls,
// so the seam cannot drift away from what ships.
func TestCngContainerImplementsTheSeam(t *testing.T) {
	var _ bindingKeyContainer = cngBindingKeyContainer{}
}

// This is the race the reviewer reproduced against the Microsoft Software KSP,
// and the one create-time NTE_EXISTS does not cover:
//
//	createA   -> success
//	createB   -> success
//	finalizeA -> success
//	finalizeB -> success
//	persisted -> B
//
// Neither create is told anything, because NCryptCreatePersistedKey does not
// write the name - NCryptFinalizeKey does - so both processes believe they made
// the key and A is left holding a handle to a key nothing will ever resolve to
// again. Only reopening the name and comparing public keys reveals it.
//
// This test is A. Its create and finalize both succeed, and the name then
// resolves to B's key; it must discard its own candidate and adopt B.
//
// It fails if the persisted-winner check is removed: without it A adopts its own
// stranded key, `adopted` holds A rather than B, and nothing is discarded.
func TestResolveBindingKeyAdoptsThePersistedWinnerAfterASilentReplace(t *testing.T) {
	const mine windows.Handle = 0xA
	const winner windows.Handle = 0xB

	c := &scriptedContainer{
		// Nothing under the name when A looks; B's key is there once A has
		// been replaced, which is what A's next pass finds.
		exists: func(opens int) (windows.Handle, bool, error) {
			if opens == 0 {
				return 0, false, nil
			}
			return winner, true, nil
		},
		// A's create and finalize both succeed. The API reports no collision.
		createFn: func(int, bool) (windows.Handle, error) { return mine, nil },
		// But the name resolves to B.
		persistedFn: func(_ int, candidate windows.Handle) (bool, error) {
			return candidate == winner, nil
		},
	}

	key, err := resolveBindingKey(c, bindingKeyName)
	if err != nil {
		t.Fatalf("resolveBindingKey: %v", err)
	}
	if key.Type != keyTypeKeyGuard {
		t.Errorf("key type = %s, want the adopted key", key.Type)
	}
	if len(c.verified) == 0 {
		t.Fatal("the candidate was never checked against the persisted key: a silent replace would go unnoticed")
	}
	if len(c.discarded) != 1 || c.discarded[0] != mine {
		t.Errorf("discarded %v, want the stranded candidate %#x released", c.discarded, mine)
	}
	if len(c.adopted) != 1 || c.adopted[0] != winner {
		t.Errorf("adopted %v, want the persisted winner %#x", c.adopted, winner)
	}
	if len(c.overwrites) != 0 && c.overwrites[len(c.overwrites)-1] {
		t.Error("the winner's key was overwritten instead of adopted")
	}
}

// The uncontended case must not pay for the check being there: when the name
// resolves to the key this process just made, that key is adopted directly and
// nothing is discarded or reopened for a second time.
func TestResolveBindingKeyAdoptsItsOwnKeyWhenItReallyWon(t *testing.T) {
	const mine windows.Handle = 0xC
	c := &scriptedContainer{
		exists:   func(int) (windows.Handle, bool, error) { return 0, false, nil },
		createFn: func(int, bool) (windows.Handle, error) { return mine, nil },
		persistedFn: func(_ int, candidate windows.Handle) (bool, error) {
			return candidate == mine, nil
		},
	}
	if _, err := resolveBindingKey(c, bindingKeyName); err != nil {
		t.Fatalf("resolveBindingKey: %v", err)
	}
	if c.creates != 1 {
		t.Errorf("create was called %d times, want 1", c.creates)
	}
	if len(c.discarded) != 0 {
		t.Errorf("the winning candidate was discarded: %v", c.discarded)
	}
	if len(c.adopted) != 1 || c.adopted[0] != mine {
		t.Errorf("adopted %v, want its own key %#x", c.adopted, mine)
	}
}

// Losing the silent race repeatedly is bounded the same way losing the reported
// one is, so a machine where creators keep replacing each other ends in a named
// error instead of an unbounded loop against the trustlet.
func TestResolveBindingKeyBoundsRepeatedSilentReplacement(t *testing.T) {
	c := &scriptedContainer{
		exists:      func(int) (windows.Handle, bool, error) { return 0, false, nil },
		createFn:    func(creates int, _ bool) (windows.Handle, error) { return windows.Handle(0x100 + creates), nil },
		persistedFn: func(int, windows.Handle) (bool, error) { return false, nil },
	}
	_, err := resolveBindingKey(c, bindingKeyName)
	if err == nil {
		t.Fatal("resolveBindingKey reported success while never being the persisted key")
	}
	if !errors.Is(err, ErrCredentialGuardNotAvailable) {
		t.Errorf("error = %v, want it to wrap ErrCredentialGuardNotAvailable", err)
	}
	if c.creates != bindingKeyCreateAttempts {
		t.Errorf("create was called %d times, want exactly %d", c.creates, bindingKeyCreateAttempts)
	}
	if len(c.discarded) != bindingKeyCreateAttempts {
		t.Errorf("discarded %d candidates, want every one released", len(c.discarded))
	}
	if len(c.adopted) != 0 {
		t.Errorf("a key was adopted on a path that failed: %v", c.adopted)
	}
}

// A verification that cannot be performed is not an excuse to use the candidate
// anyway: the whole point is that an unverified candidate may be stranded.
func TestResolveBindingKeyFailsWhenVerificationFails(t *testing.T) {
	const mine windows.Handle = 0xD
	boom := errors.New("cannot reopen the container")
	c := &scriptedContainer{
		exists:      func(int) (windows.Handle, bool, error) { return 0, false, nil },
		createFn:    func(int, bool) (windows.Handle, error) { return mine, nil },
		persistedFn: func(int, windows.Handle) (bool, error) { return false, boom },
	}
	_, err := resolveBindingKey(c, bindingKeyName)
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want the verification failure surfaced", err)
	}
	if len(c.discarded) != 1 || c.discarded[0] != mine {
		t.Errorf("discarded %v, want the unverifiable candidate released", c.discarded)
	}
	if len(c.adopted) != 0 {
		t.Errorf("an unverified candidate was adopted: %v", c.adopted)
	}
}

// ---------------------------------------------------------------------------
// NTE_EXISTS mapping.
// ---------------------------------------------------------------------------

// NTE_EXISTS means "somebody else has the name" wherever it comes from. Because
// the name is written at finalization rather than at creation, a provider may
// report the collision from NCryptFinalizeKey instead of from
// NCryptCreatePersistedKey, and mapping only the latter would turn a lost race
// into ErrCredentialGuardNotAvailable - telling the caller its host cannot do
// KeyGuard when in fact another process simply got there first.
func TestBindingKeyCreateErrorMapsNteExistsFromBothCalls(t *testing.T) {
	for _, op := range []string{"NCryptCreatePersistedKey", "NCryptFinalizeKey"} {
		if err := bindingKeyCreateError(op, uintptr(nteExists)); !errors.Is(err, errBindingKeyExists) {
			t.Errorf("%s NTE_EXISTS mapped to %v, want errBindingKeyExists", op, err)
		}
	}
	// Anything else still reports a host that cannot produce the key, and names
	// the call that failed.
	for _, op := range []string{"NCryptCreatePersistedKey", "NCryptFinalizeKey"} {
		err := bindingKeyCreateError(op, uintptr(nteNotSupported))
		if errors.Is(err, errBindingKeyExists) {
			t.Errorf("%s reported a lost race for an unrelated status", op)
		}
		if !errors.Is(err, ErrCredentialGuardNotAvailable) {
			t.Errorf("%s mapped to %v, want ErrCredentialGuardNotAvailable", op, err)
		}
		if !strings.Contains(err.Error(), op) {
			t.Errorf("error %v does not name the failing call %s", err, op)
		}
	}
}

// ---------------------------------------------------------------------------
// The cross-process lock.
// ---------------------------------------------------------------------------

// The lock name has to be derived from the container so that two containers do
// not serialize against each other, and it has to be stable so that two
// processes independently derive the same one.
func TestBindingKeyLockNameIsDeterministicAndPerContainer(t *testing.T) {
	a := bindingKeyLockSuffix(bindingKeyName)
	if a != bindingKeyLockSuffix(bindingKeyName) {
		t.Fatal("the lock name is not stable for one container")
	}
	if a == bindingKeyLockSuffix("SomeOtherContainer") {
		t.Fatal("two containers derive the same lock: unrelated identities would serialize")
	}
	// It shares the certificate store's naming scheme but must not collide with
	// it: the two guard different resources.
	if a == aliasLockSuffix(bindingKeyName) {
		t.Fatal("the key lock and the certificate store lock are the same object")
	}
	// A kernel object name may not contain a backslash except as the namespace
	// separator, and is length-limited.
	if strings.ContainsAny(a, `\/`) {
		t.Fatalf("lock suffix %q contains a path separator", a)
	}
	if len(`Global\`+a) > 260 {
		t.Fatalf("lock name is %d characters, too long for a kernel object", len(`Global\`+a))
	}
}

// The lock must actually exclude, must run the work exactly once, and must
// release afterwards so the next caller can take it.
func TestBindingKeyLockExcludesAndReleases(t *testing.T) {
	container := fmt.Sprintf("msalgo-lock-%d", time.Now().UnixNano())

	// Held on a thread of its own, because a Windows mutex is owned by a thread
	// and re-entering it from the same one would prove nothing.
	held := make(chan struct{})
	releaseIt := make(chan struct{})
	done := make(chan struct{})
	ran := 0
	go func() {
		defer close(done)
		withBindingKeyLock(container, func() {
			ran++
			close(held)
			<-releaseIt
		})
	}()
	<-held

	// A second holder on another thread must not get in while the first has it.
	// The wait degrades to running unlocked after bindingKeyLockTimeout, which
	// is far longer than this test should take, so a prompt second entry means
	// the lock did not exclude.
	entered := make(chan struct{})
	go func() {
		withBindingKeyLock(container, func() { close(entered) })
	}()
	select {
	case <-entered:
		t.Fatal("a second caller entered while the lock was held")
	case <-time.After(300 * time.Millisecond):
	}

	close(releaseIt)
	<-done
	if ran != 1 {
		t.Fatalf("the guarded work ran %d times, want 1", ran)
	}

	// Released: the queued caller gets in, and so does a fresh one.
	select {
	case <-entered:
	case <-time.After(bindingKeyLockTimeout + 5*time.Second):
		t.Fatal("the lock was never released")
	}
	third := make(chan struct{})
	go func() { withBindingKeyLock(container, func() { close(third) }) }()
	select {
	case <-third:
	case <-time.After(10 * time.Second):
		t.Fatal("the lock was not reusable after release")
	}
}

// Losing the lock entirely must not stop a key being provisioned: the lock is a
// narrowing measure, and the persisted-winner check is what makes the result
// correct. Refusing to mint a binding key because a mutex was unavailable would
// turn a hardening measure into a token outage.
//
// The namespaces are substituted rather than the container name, because the
// name is hashed - so no container string can produce an unusable object name,
// and testing fail-open through the container would silently exercise the happy
// path instead.
func TestBindingKeyLockFailsOpen(t *testing.T) {
	original := bindingKeyLockNamespaces
	// An embedded NUL cannot survive conversion to a UTF-16 object name, so no
	// handle can be obtained in either entry.
	bindingKeyLockNamespaces = []string{"bad\x00namespace", "also\x00bad"}
	t.Cleanup(func() { bindingKeyLockNamespaces = original })

	// Guard the fixture: if these ever became creatable the test would pass for
	// the wrong reason.
	for _, ns := range bindingKeyLockNamespaces {
		if _, ok := openBindingKeyLock(ns + bindingKeyLockSuffix("x")); ok {
			t.Fatalf("namespace %q unexpectedly yielded a handle", ns)
		}
	}

	ran := 0
	withBindingKeyLock("some-container", func() { ran++ })
	if ran != 1 {
		t.Fatalf("the guarded work ran %d times, want 1: provisioning was skipped because no lock could be taken", ran)
	}
}

// A busy lock must not stop provisioning, and must not run it twice. The second
// half is the regression risk in routing this through awaitNamedMutex: fn is
// invoked inside the helper when ownership is taken and by the caller when it is
// not, so a mistake there would either double-provision or skip entirely.
func TestBindingKeyLockFailsOpenWhenBusyWithoutRunningTwice(t *testing.T) {
	original := bindingKeyLockTimeout
	bindingKeyLockTimeout = 150 * time.Millisecond
	t.Cleanup(func() { bindingKeyLockTimeout = original })

	container := fmt.Sprintf("msalgo-busy-%d", time.Now().UnixNano())

	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		withBindingKeyLock(container, func() {
			close(held)
			<-release
		})
	}()
	<-held

	// The lock is held, so this caller times out and provisions unlocked.
	ran := 0
	withBindingKeyLock(container, func() { ran++ })
	if ran != 1 {
		t.Fatalf("the guarded work ran %d times while the lock was busy, want exactly 1", ran)
	}

	close(release)
	<-done
}
func TestOpenBindingKeyLockRejectsUnusableNames(t *testing.T) {
	if _, ok := openBindingKeyLock("has\x00nul"); ok {
		t.Error("a name with an embedded NUL was accepted")
	}
	// A valid name still works, which is what makes the negative meaningful.
	name := `Local\` + bindingKeyLockSuffix(fmt.Sprintf("probe-%d", time.Now().UnixNano()))
	handle, ok := openBindingKeyLock(name)
	if !ok {
		t.Fatalf("a valid name %q was rejected", name)
	}
	_ = windows.CloseHandle(handle)
}

// ---------------------------------------------------------------------------
// PSS salt length.
// ---------------------------------------------------------------------------

// crypto.Signer's contract gives the two sentinels different meanings, and
// collapsing them - which this signer used to do - makes a caller asking for
// rsa.PSSSaltLengthAuto get a hash-length salt instead of the largest the
// modulus allows. A verifier configured for the exact salt it asked for then
// rejects a signature this library produced.
func TestPSSSaltLengthDistinguishesAutoFromEqualsHash(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, csrKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	pub := &key.PublicKey
	hash := crypto.SHA256

	equalsHash, err := pssSaltLength(rsa.PSSSaltLengthEqualsHash, hash, pub)
	if err != nil {
		t.Fatalf("EqualsHash: %v", err)
	}
	if equalsHash != hash.Size() {
		t.Errorf("EqualsHash salt = %d, want %d", equalsHash, hash.Size())
	}

	auto, err := pssSaltLength(rsa.PSSSaltLengthAuto, hash, pub)
	if err != nil {
		t.Fatalf("Auto: %v", err)
	}
	// RFC 8017 9.1.1: emLen - hLen - 2, with emLen = ceil((modBits-1)/8).
	wantAuto := (pub.N.BitLen()-1+7)/8 - hash.Size() - 2
	if auto != wantAuto {
		t.Errorf("Auto salt = %d, want the encoding maximum %d", auto, wantAuto)
	}
	if auto == equalsHash {
		t.Fatal("Auto and EqualsHash resolved to the same salt, which is the bug this guards")
	}
	// It must also agree with what crypto/rsa itself accepts for Auto.
	digest := sha256.Sum256([]byte("salt length parity"))
	sig, err := rsa.SignPSS(rand.Reader, key, hash, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto, Hash: hash,
	})
	if err != nil {
		t.Fatalf("crypto/rsa SignPSS(Auto): %v", err)
	}
	if err := rsa.VerifyPSS(pub, hash, digest[:], sig, &rsa.PSSOptions{
		SaltLength: auto, Hash: hash,
	}); err != nil {
		t.Fatalf("crypto/rsa's Auto signature does not verify at salt %d: %v", auto, err)
	}
}

// Explicit lengths pass through, and values that cannot be honoured are refused
// rather than wrapped into an enormous unsigned salt.
func TestPSSSaltLengthBoundaries(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, csrKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	pub := &key.PublicKey

	if got, err := pssSaltLength(20, crypto.SHA256, pub); err != nil || got != 20 {
		t.Errorf("explicit salt = %d (err %v), want 20", got, err)
	}
	// 0 is not "an explicit zero-length salt": crypto/rsa defines
	// PSSSaltLengthAuto as 0, so it has to resolve to the encoding maximum.
	auto, err := pssSaltLength(0, crypto.SHA256, pub)
	if err != nil {
		t.Fatalf("zero (Auto): %v", err)
	}
	if want := (pub.N.BitLen()-1+7)/8 - crypto.SHA256.Size() - 2; auto != want {
		t.Errorf("zero salt = %d, want the Auto maximum %d", auto, want)
	}
	// -3 and below are not sentinels and cannot be a length.
	if _, err := pssSaltLength(-3, crypto.SHA256, pub); err == nil {
		t.Error("a negative salt length was accepted")
	}
	// A modulus too small to carry the hash yields a negative maximum, which
	// must be refused rather than converted.
	small, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pssSaltLength(rsa.PSSSaltLengthAuto, crypto.SHA512, &small.PublicKey); err == nil {
		t.Error("Auto returned a salt for a key too small to carry the hash")
	}
	if _, err := pssSaltLength(rsa.PSSSaltLengthAuto, crypto.SHA256, nil); err == nil {
		t.Error("Auto returned a salt without a public key to derive it from")
	}
}

// The CNG container this provider uses is named by MSAL .NET as well, and is
// shared with every other process on the machine. NCRYPT_OVERWRITE_KEY_FLAG
// would therefore make key creation unconditionally destructive: it replaces
// whatever is under the name, discarding a key another process may already hold
// a handle to and have a certificate issued against, turning that process's next
// handshake into a failure with no local cause. Because the key is per-boot,
// every process on the machine takes the create branch at the same moment after
// a reboot, so this is the ordinary case rather than a rare race.
//
// Omitting the flag is necessary but NOT sufficient, and it is worth being
// precise about what it buys. It removes the unconditional destruction, and it
// yields NTE_EXISTS when a rival has already finalized - which
// TestResolveBindingKeyAdoptsTheWinnerAfterLosingTheCreate covers. It does not
// make creation atomic: NCryptCreatePersistedKey does not write the name, so two
// processes can both create, both finalize, and the later finalize silently
// replaces the earlier with neither being told anything. That remaining window
// is closed by the persisted-winner check, not by this flag - see
// TestResolveBindingKeyAdoptsThePersistedWinnerAfterASilentReplace.
func TestBindingKeyCreateFlagsDoNotOverwrite(t *testing.T) {
	// NCRYPT_OVERWRITE_KEY_FLAG.
	const overwrite = 0x00000080
	if bindingKeyCreateFlags&overwrite != 0 {
		t.Fatalf("bindingKeyCreateFlags = 0x%08X, which includes NCRYPT_OVERWRITE_KEY_FLAG: "+
			"the container is shared with MSAL .NET and other processes, so creation must never replace an existing key",
			bindingKeyCreateFlags)
	}
	if bindingKeyCreateFlags&ncryptUseVirtualIsolationFlag == 0 {
		t.Error("the create flags no longer ask for VBS isolation")
	}
	if bindingKeyCreateFlags&ncryptUsePerBootKeyFlag == 0 {
		t.Error("the create flags no longer ask for a per-boot key, which IMDS requires")
	}
}

// The native library's diagnostics reach error strings, which callers log. It
// fetches its own managed identity token to call MAA and returns an MAA
// statement, and its log messages are free to quote either, so anything
// credential-shaped is replaced before it can be written to a log.
func TestAttestationDiagnosticsAreRedacted(t *testing.T) {
	jwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5cSflKxwRJSMeKKF2QT4fwpMeJf36POk"
	line := "[Error] attest AttestKeyGuard:120 MAA rejected the token " + jwt

	got := redactAttestationDetail(line)
	if strings.Contains(got, jwt) {
		t.Fatal("a credential-shaped value survived redaction")
	}
	for _, segment := range strings.Split(jwt, ".") {
		if strings.Contains(got, segment) {
			t.Fatalf("a token segment survived redaction: %q", segment)
		}
	}
	// The surrounding text is what distinguishes an MAA policy denial from a
	// missing TPM, so it has to survive.
	if !strings.Contains(got, "MAA rejected the token") {
		t.Fatalf("redaction removed the diagnostic itself: %q", got)
	}
	if !strings.Contains(got, "[Error]") || !strings.Contains(got, "AttestKeyGuard:120") {
		t.Fatalf("redaction removed the level or location: %q", got)
	}
	if !strings.Contains(got, "redacted") {
		t.Fatalf("redaction left no marker: %q", got)
	}
}

// A single line is capped on the way in, so one enormous message cannot be
// stored, let alone rendered into an error.
func TestAttestationLogLinesAreBounded(t *testing.T) {
	drainAttestationLog()
	t.Cleanup(func() { drainAttestationLog() })

	recordAttestationLog(strings.Repeat("x", attestationLogMaxLineLen*4))
	lines := drainAttestationLog()
	if len(lines) != 1 {
		t.Fatalf("recorded %d lines, want 1", len(lines))
	}
	if len(lines[0]) > attestationLogMaxLineLen+len("...(truncated)") {
		t.Fatalf("a stored line is %d bytes, want it capped at %d", len(lines[0]), attestationLogMaxLineLen)
	}
	if !strings.HasSuffix(lines[0], "(truncated)") {
		t.Fatal("a truncated line does not say so")
	}
}

// The whole transcript is capped as well, and how many were dropped is
// reported rather than silently lost.
func TestAttestationDetailIsBounded(t *testing.T) {
	lines := make([]string, attestationDetailMaxLines*3)
	for i := range lines {
		lines[i] = "diagnostic line"
	}
	detail := attestationDetail(lines)
	if strings.Count(detail, "diagnostic line") != attestationDetailMaxLines {
		t.Fatalf("rendered %d lines, want %d", strings.Count(detail, "diagnostic line"), attestationDetailMaxLines)
	}
	if !strings.Contains(detail, "more lines omitted") {
		t.Fatalf("the omission was not reported: %q", detail)
	}
	if attestationDetail(nil) != "" {
		t.Error("an empty transcript should render as nothing")
	}
}
