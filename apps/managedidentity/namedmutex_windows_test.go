// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build windows

package managedidentity

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// namedMutexAbandonEnvVar makes a test binary acquire the named mutex and exit
// while still owning it, so the parent observes WAIT_ABANDONED. Its value is the
// full object name.
const namedMutexAbandonEnvVar = "MSAL_TEST_NAMED_MUTEX_ABANDON"

const namedMutexAcquiredMarker = "NAMED_MUTEX_ACQUIRED"

func testMutexName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(`Local\msalgo-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
}

func openTestMutex(t *testing.T, name string) windows.Handle {
	t.Helper()
	encoded, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatalf("encoding %q: %v", name, err)
	}
	handle, err := windows.CreateMutex(nil, false, encoded)
	if handle == 0 {
		t.Fatalf("CreateMutex(%q): %v", name, err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(handle) })
	return handle
}

// Ownership must exclude across threads, and must be given back afterwards.
//
// Both halves matter and the second is the one that catches a release that
// silently failed: a Windows mutex is owned by a thread, so if awaitNamedMutex
// released from a thread that did not own it, ReleaseMutex would return
// ERROR_NOT_OWNER, the mutex would stay held, and this second acquisition would
// time out instead of succeeding. That makes the reuse assertion a real check on
// the release having worked, without depending on the scheduler to reproduce a
// migration.
//
// awaitNamedMutex pins its own goroutine, so the holder occupies an OS thread
// exclusively and the contender is necessarily on a different one - which is
// what makes the exclusion assertion meaningful, since a Windows mutex is
// re-entrant for the thread that already owns it.
func TestAwaitNamedMutexExcludesThenReleases(t *testing.T) {
	name := testMutexName(t)
	holderHandle := openTestMutex(t, name)
	contenderHandle := openTestMutex(t, name)

	held := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan bool, 1)
	go func() {
		holderDone <- awaitNamedMutex(holderHandle, 5*time.Second, func() {
			close(held)
			<-release
		})
	}()
	<-held

	// While it is held, a contender on another thread must not get in. A short
	// timeout is used deliberately so the negative is observed quickly; the
	// positive below is what proves the lock is not simply broken.
	busyRan := false
	if awaitNamedMutex(contenderHandle, 200*time.Millisecond, func() { busyRan = true }) {
		t.Fatal("a second caller acquired the mutex while it was held")
	}
	if busyRan {
		t.Fatal("the guarded work ran without ownership")
	}

	close(release)
	if !<-holderDone {
		t.Fatal("the holder reported it never acquired the mutex")
	}

	// Released: the same contender now gets in promptly. A failed ReleaseMutex
	// would leave this timing out.
	reuseRan := false
	if !awaitNamedMutex(contenderHandle, 5*time.Second, func() { reuseRan = true }) {
		t.Fatal("the mutex was never released: ownership could not be reacquired")
	}
	if !reuseRan {
		t.Fatal("ownership was reported without the work running")
	}
}

// The wait, the work and the release have to happen on one OS thread. This
// observes the pinning directly rather than trying to provoke a crash: the
// thread identity is sampled repeatedly inside the guarded work, across
// scheduling points that park the goroutine and hand its thread to somebody
// else, and under runtime.LockOSThread it cannot change.
//
// On correct code this is deterministic - pinning makes the identity constant,
// so it never fails spuriously. In the other direction it is a strong but not
// absolute detector: an unpinned goroutine is *allowed* to resume on the same
// thread, so a single sample could miss the fault. The sampling is repeated,
// and other goroutines are kept runnable to occupy the remaining threads, to
// make resuming elsewhere the overwhelmingly likely outcome. A test that forced
// the migration deterministically would have to depend on runtime scheduling
// internals, which is exactly the kind of flakiness worth avoiding.
func TestAwaitNamedMutexPinsTheOSThread(t *testing.T) {
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("needs more than one usable thread to observe a migration")
	}
	name := testMutexName(t)
	handle := openTestMutex(t, name)

	// Keep the other threads busy so a goroutine that parks is unlikely to be
	// handed back the thread it left.
	stop := make(chan struct{})
	for i := 0; i < runtime.GOMAXPROCS(0); i++ {
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					runtime.Gosched()
				}
			}
		}()
	}
	t.Cleanup(func() { close(stop) })

	var ids []uint32
	ok := awaitNamedMutex(handle, 10*time.Second, func() {
		for i := 0; i < 32; i++ {
			ids = append(ids, windows.GetCurrentThreadId())
			// Sleeping parks the goroutine and releases its thread, which is
			// the point at which an unpinned one is free to come back on a
			// different one.
			time.Sleep(time.Millisecond)
			runtime.Gosched()
		}
		ids = append(ids, windows.GetCurrentThreadId())
	})
	if !ok {
		t.Fatal("the mutex was not acquired")
	}
	for _, id := range ids {
		if id == 0 {
			t.Fatal("the thread id was not sampled")
		}
		if id != ids[0] {
			t.Fatalf("the guarded work moved between OS threads (%d then %d): ReleaseMutex would fail with ERROR_NOT_OWNER and the mutex would stay held for the life of the process", ids[0], id)
		}
	}
}

// A process that dies owning the mutex abandons it. The next waiter is told
// WAIT_ABANDONED rather than WAIT_OBJECT_0, and must treat that as ownership:
// reading it as a failure would mean one crashed process disabled the lock for
// everybody until the object went away.
//
// This is driven with a real child process, because abandonment cannot be
// simulated in-process - it requires an owning thread to disappear.
func TestAwaitNamedMutexTreatsAbandonedAsAcquired(t *testing.T) {
	if name := os.Getenv(namedMutexAbandonEnvVar); name != "" {
		abandonNamedMutexChild(name)
		return
	}

	name := testMutexName(t)
	// The parent holds a handle throughout, so the object outlives the child
	// and the parent really does inherit an abandoned mutex rather than
	// creating a fresh one.
	handle := openTestMutex(t, name)

	// #nosec G204 -- the command is this test binary and the arguments are
	// constants.
	cmd := exec.Command(os.Args[0], "-test.run=^TestAwaitNamedMutexTreatsAbandonedAsAcquired$", "-test.v")
	cmd.Env = append(os.Environ(), namedMutexAbandonEnvVar+"="+name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the abandoning child failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), namedMutexAcquiredMarker) {
		t.Fatalf("the child never acquired the mutex, so nothing was abandoned:\n%s", out)
	}

	ran := false
	if !awaitNamedMutex(handle, 5*time.Second, func() { ran = true }) {
		t.Fatal("an abandoned mutex was not treated as acquired")
	}
	if !ran {
		t.Fatal("ownership was reported without the work running")
	}

	// And it was released again, not left abandoned a second time.
	if !awaitNamedMutex(handle, 5*time.Second, func() {}) {
		t.Fatal("the mutex was not released after being adopted from an abandoned state")
	}
}

// abandonNamedMutexChild takes ownership and exits without releasing.
func abandonNamedMutexChild(name string) {
	encoded, err := windows.UTF16PtrFromString(name)
	if err != nil {
		os.Exit(2)
	}
	handle, err := windows.CreateMutex(nil, false, encoded)
	if handle == 0 {
		_ = err
		os.Exit(3)
	}
	// Take ownership on this thread, announce it, and die holding it.
	runtime.LockOSThread()
	event, err := windows.WaitForSingleObject(handle, 5000)
	if err != nil || (event != windows.WAIT_OBJECT_0 && event != uint32(windows.WAIT_ABANDONED)) {
		os.Exit(4)
	}
	fmt.Println(namedMutexAcquiredMarker)
	os.Stdout.Sync()
	os.Exit(0)
}

// Clamping keeps a wait bounded. A duration at or beyond INFINITE would
// otherwise become an unbounded wait, hanging an acquisition behind whatever
// holds the mutex, and a negative one would be reinterpreted as enormous.
func TestWaitMillisecondsClamps(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout time.Duration
		want    uint32
	}{
		{"ordinary", 300 * time.Millisecond, 300},
		{"sub-millisecond rounds down to a poll", 10 * time.Microsecond, 0},
		{"zero", 0, 0},
		{"negative", -time.Second, 0},
		{"at INFINITE", time.Duration(0xFFFFFFFF) * time.Millisecond, 0xFFFFFFFE},
		{"beyond INFINITE", time.Duration(1<<62 - 1), 0xFFFFFFFE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := waitMilliseconds(tc.timeout); got != tc.want {
				t.Fatalf("waitMilliseconds(%v) = %d, want %d", tc.timeout, got, tc.want)
			}
		})
	}
	// The clamp must never produce INFINITE itself.
	if waitMilliseconds(time.Duration(1<<62-1)) == 0xFFFFFFFF {
		t.Fatal("a clamped wait became INFINITE")
	}
}

// ---------------------------------------------------------------------------
// The certificate store's alias lock, which shares the primitive.
// ---------------------------------------------------------------------------

// The store lock has the same thread-affinity requirement as the key lock, and
// getting it wrong there is quiet and lasting: the release fails with
// ERROR_NOT_OWNER, the mutex stays held for the life of the process, and every
// later write in every process times out and silently skips persistence.
//
// Exclusion is asserted while it is held, and reuse afterwards proves the
// release actually worked.
func TestAliasLockExcludesThenReleases(t *testing.T) {
	alias := fmt.Sprintf("msalgo-alias-%d-%d", os.Getpid(), time.Now().UnixNano())

	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	holderRan := 0
	go func() {
		defer close(done)
		withAliasLock(alias, func() {
			holderRan++
			close(held)
			<-release
		})
	}()
	<-held

	// persistLockTimeout is short by design, so a contender gives up quickly
	// and skips the write rather than delaying a token.
	busyRan := false
	withAliasLock(alias, func() { busyRan = true })
	if busyRan {
		t.Fatal("a second caller wrote the store while the alias lock was held")
	}

	close(release)
	<-done
	if holderRan != 1 {
		t.Fatalf("the guarded work ran %d times, want 1", holderRan)
	}

	// Released: a later write gets the lock again. If the release had failed,
	// this would skip for the rest of the process.
	reuseRan := false
	withAliasLock(alias, func() { reuseRan = true })
	if !reuseRan {
		t.Fatal("the alias lock was never released: later writes would silently skip persistence")
	}
}

// Two aliases must not serialize against each other, or persisting for one
// identity would block persisting for another.
func TestAliasLockIsPerAlias(t *testing.T) {
	first := fmt.Sprintf("msalgo-alias-a-%d", time.Now().UnixNano())
	second := fmt.Sprintf("msalgo-alias-b-%d", time.Now().UnixNano())

	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		withAliasLock(first, func() {
			close(held)
			<-release
		})
	}()
	<-held

	otherRan := false
	withAliasLock(second, func() { otherRan = true })
	if !otherRan {
		t.Fatal("holding one alias's lock blocked an unrelated alias")
	}

	close(release)
	<-done
}
