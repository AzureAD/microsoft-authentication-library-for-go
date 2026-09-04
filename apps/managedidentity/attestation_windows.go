// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// attestationLibName is resolved only from the directory holding the host
// executable, any directory the process added with AddDllDirectory, and
// System32. It is deliberately not loaded through the standard search order,
// which would also search the current working directory and every PATH entry
// and would let any principal able to write to one of those load arbitrary
// native code into a process that holds managed identity tokens and a live
// KeyGuard key handle.
const attestationLibName = "AttestationClientLib.dll"

// LoadLibraryEx search flags. Passing any LOAD_LIBRARY_SEARCH_* flag replaces
// the standard search order with the restricted set named by the flags, so
// neither the working directory nor PATH is consulted.
const (
	loadLibrarySearchApplicationDir = 0x00000200
	loadLibrarySearchSystem32       = 0x00000800
	loadLibrarySearchDefaultDirs    = 0x00001000
)

// attestationLogInfo mirrors the AttestationLogInfo struct the native library
// expects: a callback and an opaque context pointer.
type attestationLogInfo struct {
	log uintptr
	ctx uintptr
}

// nativeLogLevel values as the native library defines them.
var nativeLogLevels = [...]string{"error", "warn", "info", "debug"}

type attestationLib struct {
	attestKeyGuardImportKey uintptr
	freeAttestationToken    uintptr
}

var (
	attestationLibOnce sync.Once
	attestationLibVal  *attestationLib
	attestationLibErr  error
)

// attestationLog collects what the native library reports. The library is a
// black box whose failures are otherwise a bare integer, so its own diagnostics
// are the only way to tell an MAA policy denial from a missing TPM.
var attestationLog struct {
	mu    sync.Mutex
	lines []string
}

// attestationCallMu keeps one attestation at a time from drain to collection.
//
// attestationLog is process-wide because the native library's callback carries
// no key or request identity, so two concurrent attestations would interleave
// their diagnostics and each would report the other's lines as the reason it
// failed. These lines are the only way to tell an MAA policy denial from a
// missing TPM, so a wrong one is worse than none.
var attestationCallMu sync.Mutex

func recordAttestationLog(line string) {
	attestationLog.mu.Lock()
	defer attestationLog.mu.Unlock()
	// Bounded so a chatty library cannot grow this without limit.
	if len(attestationLog.lines) >= 256 {
		return
	}
	attestationLog.lines = append(attestationLog.lines, line)
}

func drainAttestationLog() []string {
	attestationLog.mu.Lock()
	defer attestationLog.mu.Unlock()
	out := attestationLog.lines
	attestationLog.lines = nil
	return out
}

// attestationLogThunk is the native logging callback. The pointer arguments are
// declared as *byte rather than uintptr so no uintptr is ever reinterpreted as
// a pointer, which is both unsafe and something go vet correctly rejects.
func attestationLogThunk(ctx uintptr, tag *byte, level uintptr, function *byte, line uintptr, message *byte) uintptr {
	levelName := "unknown"
	// level is unsigned, so a bounds check alone is enough; converting to a
	// signed type here would be a needless narrowing.
	if level < uintptr(len(nativeLogLevels)) {
		levelName = nativeLogLevels[level]
	}
	recordAttestationLog(fmt.Sprintf("[%s] %s %s:%d %s",
		levelName,
		windows.BytePtrToString(tag),
		windows.BytePtrToString(function),
		line,
		windows.BytePtrToString(message)))
	return 0
}

// loadAttestationLib resolves the native library once. A missing library is
// reported as ErrAttestationUnavailable so the caller can tell a deployment gap
// apart from a real failure, while a library that is present but unusable
// produces a real error.
func loadAttestationLib() (*attestationLib, error) {
	attestationLibOnce.Do(func() {
		handle, err := windows.LoadLibraryEx(attestationLibName, 0,
			loadLibrarySearchApplicationDir|loadLibrarySearchSystem32|loadLibrarySearchDefaultDirs)
		if err != nil {
			// A failed load reports ERROR_MOD_NOT_FOUND whether the library
			// itself is absent or one of its own dependencies is, so the error
			// alone cannot tell a host that never deployed it from a host that
			// deployed it without the Visual C++ runtime it links against.
			// Locating the file separates the two: only the first case is a
			// fallback, because silently downgrading a deployment that meant to
			// attest would resurface as an unexplained rejection from IMDS.
			if path, findErr := findAttestationLib(); findErr == nil {
				attestationLibErr = fmt.Errorf("loading %s: %v; the library is present but could not be loaded, which usually means a dependency is missing, such as the Visual C++ runtime (MSVCP140.dll, VCRUNTIME140.dll)", path, err)
				return
			}
			attestationLibErr = fmt.Errorf("%w: loading %s: %v", ErrAttestationUnavailable, attestationLibName, err)
			return
		}
		var initLib, attest, free uintptr
		for _, p := range []struct {
			name string
			addr *uintptr
		}{
			{"InitAttestationLib", &initLib},
			{"AttestKeyGuardImportKey", &attest},
			{"FreeAttestationToken", &free},
		} {
			addr, err := windows.GetProcAddress(handle, p.name)
			if err != nil {
				attestationLibErr = fmt.Errorf("%w: %s is missing %s: %v", ErrAttestationUnavailable, attestationLibName, p.name, err)
				return
			}
			*p.addr = addr
		}

		info := attestationLogInfo{log: windows.NewCallback(attestationLogThunk)}
		if r, _, err := syscall.SyscallN(initLib, uintptr(unsafe.Pointer(&info))); r != 0 {
			// #nosec G115 -- the native library returns a 32-bit HRESULT-style
			// status widened into a uintptr by the syscall ABI, so narrowing it
			// back to int32 restores the value the library actually returned.
			attestationLibErr = fmt.Errorf("managedidentity: InitAttestationLib returned %d: %v", int32(r), err)
			return
		}
		// info holds a pointer to a Go callback for the lifetime of the process.
		// The library is deliberately never uninitialised: doing so would race
		// with any in-flight attestation on another goroutine, and the process
		// exiting reclaims it anyway.
		attestationLibVal = &attestationLib{attestKeyGuardImportKey: attest, freeAttestationToken: free}
	})
	return attestationLibVal, attestationLibErr
}

// findAttestationLib reports where the library is deployed, so a load failure
// caused by a missing dependency can be told apart from the library simply not
// being deployed. It checks exactly the directories loadAttestationLib is
// willing to load from, so a file found here is one that would have loaded.
func findAttestationLib() (string, error) {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if sys, err := windows.GetSystemDirectory(); err == nil {
		dirs = append(dirs, sys)
	}
	for _, dir := range dirs {
		path := filepath.Join(dir, attestationLibName)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s was not found in the application directory or System32", attestationLibName)
}

// attestKeyGuard asks the native library for an MAA statement over key. It
// returns ErrAttestationUnavailable when the library is not deployed, so the
// caller can tell an undeployed library apart from a statement the service
// refused.
func attestKeyGuard(endpoint, clientID string, key bindingKey) (string, error) {
	// Only a VBS-isolated key can be attested: MAA has nothing to vouch for
	// when the private material never entered a trustlet. A caller who asked
	// for attestation and holds a software or TPM key is told so rather than
	// downgraded, which is also how MSAL .NET treats a key that is not RSACng.
	if key.Type != keyTypeKeyGuard {
		return "", fmt.Errorf("%w: the binding key is not KeyGuard-isolated", ErrAttestationUnavailable)
	}
	signer, ok := key.Signer.(*ncryptSigner)
	if !ok {
		return "", fmt.Errorf("%w: the binding key is not a CNG key", ErrAttestationUnavailable)
	}
	lib, err := loadAttestationLib()
	if err != nil {
		return "", err
	}

	endpointPtr, err := windows.BytePtrFromString(endpoint)
	if err != nil {
		return "", fmt.Errorf("managedidentity: the attestation endpoint is not usable: %w", err)
	}
	clientIDPtr, err := windows.BytePtrFromString(clientID)
	if err != nil {
		return "", fmt.Errorf("managedidentity: the client ID is not usable: %w", err)
	}

	// The native library writes its diagnostics into one process-wide buffer, so
	// a concurrent attestation for another key would take the lines that explain
	// this one's failure. attestation.go's gate only serializes callers that
	// share a cache key, so the drain, the call, and the collection of the log
	// are held together here.
	attestationCallMu.Lock()
	defer attestationCallMu.Unlock()

	// The handle stays locked for the duration of the call. Sign holds the same
	// lock for the same reason: without it Close could free the key while the
	// trustlet is still using it.
	signer.mu.Lock()
	defer signer.mu.Unlock()
	if signer.closed || signer.key == 0 {
		return "", fmt.Errorf("managedidentity: the binding key handle is already released")
	}
	handle := signer.key

	drainAttestationLog()
	// token is a *byte rather than a uintptr so the returned C string is never
	// reconstructed from an integer.
	var token *byte
	// authToken and clientPayload are null: the library fetches its own managed
	// identity token from IMDS, which is what MSAL .NET passes too.
	r, _, callErr := syscall.SyscallN(lib.attestKeyGuardImportKey,
		uintptr(unsafe.Pointer(endpointPtr)),
		0,
		0,
		uintptr(handle),
		uintptr(unsafe.Pointer(&token)),
		uintptr(unsafe.Pointer(clientIDPtr)),
	)
	// Keep the argument memory alive across the call.
	runtime.KeepAlive(endpointPtr)
	runtime.KeepAlive(clientIDPtr)

	// #nosec G115 -- the native library returns a 32-bit status widened into a
	// uintptr by the syscall ABI; narrowing it back to int32 restores the value
	// the library actually returned, including negative failure codes.
	if code := int32(r); code != 0 || token == nil {
		detail := strings.Join(drainAttestationLog(), "; ")
		if detail == "" {
			detail = "the native library reported no detail"
		}
		return "", fmt.Errorf("managedidentity: KeyGuard attestation failed with native code %d (%v): %s", code, callErr, detail)
	}
	jwt := windows.BytePtrToString(token)
	_, _, _ = syscall.SyscallN(lib.freeAttestationToken, uintptr(unsafe.Pointer(token)))
	if jwt == "" {
		return "", fmt.Errorf("managedidentity: KeyGuard attestation produced an empty token: %s",
			strings.Join(drainAttestationLog(), "; "))
	}
	return jwt, nil
}
