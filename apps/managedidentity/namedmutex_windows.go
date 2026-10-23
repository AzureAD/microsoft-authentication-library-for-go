// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build windows

package managedidentity

import (
	"runtime"
	"time"

	"golang.org/x/sys/windows"
)

// awaitNamedMutex waits up to timeout for ownership of handle, runs fn if
// ownership is taken, and releases it afterwards. It reports whether fn ran.
//
// Two subsystems in this package take a named Windows mutex - the binding key
// container in keyprovider_windows.go and the certificate store in
// imdsv2_persist_windows.go - and the part they must not get wrong is identical,
// so it lives here once rather than being written twice and drifting.
//
// The OS thread is pinned across the whole wait-fn-release span, and that is the
// reason this function exists. A Windows mutex is owned by a *thread*, not by a
// process and not by a goroutine. Go is free to resume a goroutine on a
// different OS thread after any call that can yield - which fn certainly can -
// and ReleaseMutex called from a thread that does not own the mutex fails with
// ERROR_NOT_OWNER. Nothing then releases it: the mutex stays held until this
// process exits, every other process waiting on it times out, and because the
// release error is not actionable at runtime it is discarded, so the failure is
// completely silent. runtime.LockOSThread is what makes the release land on the
// thread that took ownership.
//
// Ownership is released exactly once and only when it was actually taken. A
// timeout or a failed wait means somebody else holds it, so there is nothing to
// release and fn must not run. Callers that want to proceed without the lock
// must do so after this returns false, never inside fn, or the work would run
// twice.
//
// The handle is not closed here; it belongs to the caller, whose own deferred
// close runs after the release and the unpin.
func awaitNamedMutex(handle windows.Handle, timeout time.Duration, fn func()) bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	event, err := windows.WaitForSingleObject(handle, waitMilliseconds(timeout))
	switch {
	case err != nil:
		// WAIT_FAILED. The wait itself did not work, so no ownership was taken
		// and nothing may be released. x/sys sets err only for this case, so a
		// timeout does not reach here.
		return false
	case event == windows.WAIT_OBJECT_0 || event == uint32(windows.WAIT_ABANDONED):
		// WAIT_ABANDONED means the previous owner died without releasing. The
		// mutex is ours either way, and it still has to be released or the next
		// waiter inherits the same problem. Neither caller has partial state to
		// roll back: the certificate store is self-describing, and the key
		// provider re-reads the persisted key before trusting it.
		defer func() { _ = windows.ReleaseMutex(handle) }()
		fn()
		return true
	default:
		// WAIT_TIMEOUT. Somebody else holds it.
		return false
	}
}

// waitMilliseconds renders a timeout as the millisecond count
// WaitForSingleObject takes, clamping instead of wrapping.
//
// The clamp is not only about the conversion being in range. INFINITE is
// 0xFFFFFFFF, so a duration that wrapped or saturated to that value would turn a
// bounded wait into one that never returns, hanging a token acquisition behind
// whatever holds the mutex. Anything at or above that is pinned one below, and a
// non-positive timeout becomes a zero-length poll rather than a negative number
// reinterpreted as an enormous one.
func waitMilliseconds(timeout time.Duration) uint32 {
	// One below INFINITE, so a wait is always bounded.
	const maxWait = 0xFFFFFFFE
	ms := timeout / time.Millisecond
	switch {
	case ms <= 0:
		return 0
	case ms >= maxWait:
		return maxWait
	default:
		// #nosec G115 -- the guards above bound ms to (0, maxWait), which is
		// inside uint32.
		return uint32(ms)
	}
}
