// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build windows && amd64
// +build windows,amd64

package attestation

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	managedidentity "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
	"golang.org/x/sys/windows"
)

const (
	dllName           = "AttestationClientLib.dll"
	packageVersion    = "1.1.5"
	expectedDLLSHA256 = "90dfcce20e1a74519b49796eeee17e6e59a257c3acf754f454a49380d28a568b"

	loadLibrarySearchSystem32 = 0x00000800
	moveFileReplaceExisting   = 0x00000001
	moveFileWriteThrough      = 0x00000008

	// Extraction is on the token-acquisition path, whose live E2E bound is 30
	// seconds. Five seconds gives another process ample time to publish the
	// 5.3 MiB asset without leaving this process blocked indefinitely.
	extractionLockTimeout      = 5 * time.Second
	extractionLockRetryInitial = 10 * time.Millisecond
	extractionLockRetryMaximum = 100 * time.Millisecond

	winTrustUINone             = 2
	winTrustRevokeNone         = 0
	winTrustChoiceFile         = 1
	winTrustStateActionVerify  = 1
	winTrustStateActionClose   = 2
	winTrustRevocationNone     = 0x00000010
	winTrustCacheOnlyURLLookup = 0x00001000
)

var (
	errDLLIntegrity  = errors.New("attestation: DLL integrity verification failed")
	errDLLSignature  = errors.New("attestation: DLL Authenticode verification failed")
	errDLLPathUnsafe = errors.New("attestation: DLL path is unsafe")

	winTrustActionGenericVerifyV2 = windows.GUID{
		Data1: 0x00AAC56B,
		Data2: 0xCD44,
		Data3: 0x11D0,
		Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
	}
	wintrust       = windows.NewLazySystemDLL("wintrust.dll")
	winVerifyTrust = wintrust.NewProc("WinVerifyTrust")
)

//go:embed native/AttestationClientLib.dll
var embeddedDLL []byte

type libraryProvider struct {
	mu     sync.Mutex
	handle windows.Handle

	// Tests override these to isolate the stable per-user location and observe
	// the path handed to LoadLibraryEx. Production leaves both unset.
	path   string
	loader func(string) (windows.Handle, error)
}

type unavailableError struct {
	cause error
}

func (e unavailableError) Error() string {
	return fmt.Sprintf("attestation: native library unavailable: %v", e.cause)
}

func (e unavailableError) Unwrap() error {
	return e.cause
}

func (e unavailableError) Is(target error) bool {
	return target == managedidentity.ErrAttestationUnavailable
}

func asUnavailable(err error) error {
	if errors.Is(err, managedidentity.ErrAttestationUnavailable) {
		return err
	}
	return unavailableError{cause: err}
}

func (p *libraryProvider) LoadAttestationLibrary() (uintptr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.handle != 0 {
		return uintptr(p.handle), nil
	}

	path := p.path
	if path == "" {
		var err error
		path, err = attestationDLLPath()
		if err != nil {
			return 0, asUnavailable(err)
		}
	}
	loader := p.loader
	if loader == nil {
		loader = loadAttestationDLL
	}

	handle, err := materializeAndLoad(path, loader)
	if err != nil {
		return 0, asUnavailable(err)
	}
	p.handle = handle
	return uintptr(handle), nil
}

func attestationDLLPath() (string, error) {
	localAppData, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil {
		return "", fmt.Errorf("finding LocalAppData: %w", err)
	}
	path := filepath.Join(localAppData, "Microsoft", "MSAL", "attestation", packageVersion, "win-x64", dllName)
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("LocalAppData produced a non-absolute attestation path %q", path)
	}
	return path, nil
}

func materializeAndLoad(path string, loader func(string) (windows.Handle, error)) (handle windows.Handle, err error) {
	if err := verifyEmbeddedDLL(); err != nil {
		return 0, err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return 0, fmt.Errorf("resolving the attestation library path: %w", err)
	}

	// Create missing directories one component at a time under already pinned
	// parents. Holding every handle without delete sharing prevents ancestry
	// replacement through verification and load while still allowing publication.
	ancestors, err := prepareAndPinDirectory(filepath.Dir(path))
	if err != nil {
		return 0, fmt.Errorf("preparing the attestation library directory: %w", err)
	}
	defer func() {
		if closeErr := ancestors.close(); closeErr != nil {
			if err != nil {
				err = fmt.Errorf("%v; %w", err, closeErr)
				return
			}
			if handle != 0 {
				if freeErr := windows.FreeLibrary(handle); freeErr != nil {
					closeErr = fmt.Errorf("%v; unloading after that failure: %w", closeErr, freeErr)
				}
				handle = 0
			}
			err = closeErr
		}
	}()

	lock, err := acquireExtractionLock(path + ".lock")
	if err != nil {
		return 0, err
	}
	defer func() {
		if releaseErr := lock.release(); releaseErr != nil {
			if err != nil {
				err = fmt.Errorf("%v; %w", err, releaseErr)
				return
			}
			if handle != 0 {
				if freeErr := windows.FreeLibrary(handle); freeErr != nil {
					releaseErr = fmt.Errorf("%v; unloading after that failure: %w", releaseErr, freeErr)
				}
				handle = 0
			}
			err = releaseErr
		}
	}()

	handle, err = verifyAndLoad(path, loader)
	if err == nil {
		return handle, nil
	}
	if !errors.Is(err, errDLLIntegrity) && !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}

	temp, err := writeEmbeddedDLL(filepath.Dir(path))
	if err != nil {
		return 0, err
	}
	defer func() {
		if temp == "" {
			return
		}
		if removeErr := os.Remove(temp); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			if err != nil {
				err = fmt.Errorf("%v; removing temporary attestation library %q: %w", err, temp, removeErr)
			} else {
				err = fmt.Errorf("removing temporary attestation library %q: %w", temp, removeErr)
			}
		}
	}()
	if err := verifyDLLFile(temp); err != nil {
		return 0, fmt.Errorf("verifying the extracted attestation library: %w", err)
	}
	if err := atomicReplace(temp, path); err != nil {
		return 0, fmt.Errorf("installing the attestation library: %w", err)
	}
	temp = ""
	return verifyAndLoad(path, loader)
}

func verifyEmbeddedDLL() error {
	sum := sha256.Sum256(embeddedDLL)
	if got := hex.EncodeToString(sum[:]); got != expectedDLLSHA256 {
		return fmt.Errorf("%w: embedded SHA-256 is %s, expected %s", errDLLIntegrity, got, expectedDLLSHA256)
	}
	return nil
}

func writeEmbeddedDLL(dir string) (path string, err error) {
	file, err := os.CreateTemp(dir, ".AttestationClientLib-*.tmp")
	if err != nil {
		return "", fmt.Errorf("creating a temporary attestation library: %w", err)
	}
	path = file.Name()
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("closing temporary attestation library: %w", closeErr)
		}
		if err != nil {
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = fmt.Errorf("%v; removing temporary attestation library %q: %w", err, path, removeErr)
			}
		}
	}()

	written, err := io.Copy(file, bytes.NewReader(embeddedDLL))
	if err != nil {
		return path, fmt.Errorf("writing the embedded attestation library: %w", err)
	}
	if written != int64(len(embeddedDLL)) {
		return path, fmt.Errorf("writing the embedded attestation library: wrote %d bytes, expected %d", written, len(embeddedDLL))
	}
	if err := file.Sync(); err != nil {
		return path, fmt.Errorf("flushing the embedded attestation library: %w", err)
	}
	return path, nil
}

func atomicReplace(from, to string) error {
	fromPtr, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return fmt.Errorf("encoding temporary path: %w", err)
	}
	toPtr, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return fmt.Errorf("encoding destination path: %w", err)
	}
	return windows.MoveFileEx(fromPtr, toPtr, moveFileReplaceExisting|moveFileWriteThrough)
}

type extractionLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

type extractionLockPolicy struct {
	timeout      time.Duration
	initialRetry time.Duration
	maximumRetry time.Duration
	now          func() time.Time
	wait         func(time.Duration)
	onContention func()
}

var defaultExtractionLockPolicy = extractionLockPolicy{
	timeout:      extractionLockTimeout,
	initialRetry: extractionLockRetryInitial,
	maximumRetry: extractionLockRetryMaximum,
	now:          time.Now,
	wait:         time.Sleep,
}

func acquireExtractionLock(path string) (*extractionLock, error) {
	return acquireExtractionLockWithPolicy(path, defaultExtractionLockPolicy)
}

func acquireExtractionLockWithPolicy(path string, policy extractionLockPolicy) (*extractionLock, error) {
	if policy.timeout <= 0 || policy.initialRetry <= 0 || policy.maximumRetry < policy.initialRetry ||
		policy.now == nil || policy.wait == nil {
		return nil, errors.New("acquiring the attestation extraction lock: invalid wait policy")
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encoding the extraction lock path: %w", err)
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("opening the extraction lock: %w", err)
	}
	lock := &extractionLock{
		file: os.NewFile(uintptr(handle), path),
	}
	if lock.file == nil {
		if closeErr := windows.CloseHandle(handle); closeErr != nil {
			return nil, fmt.Errorf("opening the extraction lock: os.NewFile returned nil; closing its handle: %w", closeErr)
		}
		return nil, errors.New("opening the extraction lock: os.NewFile returned nil")
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, lock.closeAfterError(fmt.Errorf("inspecting the extraction lock: %w", err))
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, lock.closeAfterError(fmt.Errorf("%w: extraction lock %q is a reparse point", errDLLPathUnsafe, path))
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return nil, lock.closeAfterError(fmt.Errorf("%w: extraction lock %q is not a regular file", errDLLPathUnsafe, path))
	}

	deadline := policy.now().Add(policy.timeout)
	delay := policy.initialRetry
	for {
		lock.overlapped = windows.Overlapped{}
		err := windows.LockFileEx(
			handle,
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0,
			1,
			0,
			&lock.overlapped,
		)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, lock.closeAfterError(fmt.Errorf("locking the attestation extraction path: %w", err))
		}
		if policy.onContention != nil {
			policy.onContention()
		}

		now := policy.now()
		if !now.Before(deadline) {
			timeoutErr := fmt.Errorf(
				"timed out after %s waiting for another process to publish the attestation library: %w",
				policy.timeout,
				err,
			)
			return nil, lock.closeAfterError(asUnavailable(timeoutErr))
		}
		remaining := deadline.Sub(now)
		if delay > remaining {
			delay = remaining
		}
		policy.wait(delay)
		if delay < policy.maximumRetry {
			delay *= 2
			if delay > policy.maximumRetry {
				delay = policy.maximumRetry
			}
		}
	}
}

func (l *extractionLock) closeAfterError(err error) error {
	if closeErr := l.file.Close(); closeErr != nil {
		return fmt.Errorf("%v; closing the extraction lock: %w", err, closeErr)
	}
	return err
}

func (l *extractionLock) release() error {
	handle := windows.Handle(l.file.Fd())
	unlockErr := windows.UnlockFileEx(handle, 0, 1, 0, &l.overlapped)
	closeErr := l.file.Close()
	switch {
	case unlockErr != nil && closeErr != nil:
		return fmt.Errorf("releasing the attestation extraction lock: %v; closing it: %w", unlockErr, closeErr)
	case unlockErr != nil:
		return fmt.Errorf("releasing the attestation extraction lock: %w", unlockErr)
	case closeErr != nil:
		return fmt.Errorf("closing the attestation extraction lock: %w", closeErr)
	default:
		return nil
	}
}

func verifyDLLFile(path string) (err error) {
	file, err := openVerifiedDLL(path)
	if err != nil {
		return err
	}
	if closeErr := file.close(); closeErr != nil {
		return closeErr
	}
	return nil
}

func verifyAndLoad(path string, loader func(string) (windows.Handle, error)) (handle windows.Handle, err error) {
	file, err := openVerifiedDLL(path)
	if err != nil {
		return 0, err
	}
	defer func() {
		if closeErr := file.close(); closeErr != nil {
			if err != nil {
				err = fmt.Errorf("%v; closing the verified attestation library: %w", err, closeErr)
				return
			}
			if handle != 0 {
				if freeErr := windows.FreeLibrary(handle); freeErr != nil {
					closeErr = fmt.Errorf("%v; unloading after that failure: %w", closeErr, freeErr)
				}
				handle = 0
			}
			err = fmt.Errorf("closing the verified attestation library: %w", closeErr)
		}
	}()

	handle, err = loader(file.canonicalPath)
	if err != nil {
		return 0, fmt.Errorf("loading the verified attestation library %q by absolute path: %w", file.canonicalPath, err)
	}
	if handle == 0 {
		return 0, fmt.Errorf("loading the verified attestation library %q by absolute path returned an invalid handle", file.canonicalPath)
	}
	return handle, nil
}

type fileIdentity struct {
	volumeSerialNumber uint32
	fileIndexHigh      uint32
	fileIndexLow       uint32
}

type pinnedHandles struct {
	handles []windows.Handle
}

func (p *pinnedHandles) closeAfterError(err error) error {
	if closeErr := p.close(); closeErr != nil {
		return fmt.Errorf("%v; %w", err, closeErr)
	}
	return err
}

func (p *pinnedHandles) close() error {
	var first error
	for i := len(p.handles) - 1; i >= 0; i-- {
		if err := windows.CloseHandle(p.handles[i]); err != nil && first == nil {
			first = err
		}
	}
	p.handles = nil
	if first != nil {
		return fmt.Errorf("closing a pinned attestation path handle: %w", first)
	}
	return nil
}

type verifiedDLL struct {
	file          *os.File
	pins          pinnedHandles
	canonicalPath string
	identity      fileIdentity
}

func (v *verifiedDLL) close() error {
	var first error
	if v.file != nil {
		if err := v.file.Close(); err != nil {
			first = err
		}
		v.file = nil
	}
	if err := v.pins.close(); err != nil && first == nil {
		first = err
	}
	if first != nil {
		return fmt.Errorf("closing the verified attestation library: %w", first)
	}
	return nil
}

func openVerifiedDLL(path string) (*verifiedDLL, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving the attestation library path: %w", err)
	}
	verified := &verifiedDLL{}
	closeOnError := func(err error) (*verifiedDLL, error) {
		if closeErr := verified.close(); closeErr != nil {
			err = fmt.Errorf("%v; %w", err, closeErr)
		}
		return nil, err
	}

	requestedPins, err := pinPathAncestors(absolutePath)
	if err != nil {
		return nil, err
	}
	verified.pins.handles = append(verified.pins.handles, requestedPins.handles...)
	requestedPins.handles = nil

	handle, info, err := openPinnedPathComponent(absolutePath, false)
	if err != nil {
		return closeOnError(err)
	}
	file := os.NewFile(uintptr(handle), absolutePath)
	if file == nil {
		if closeErr := windows.CloseHandle(handle); closeErr != nil {
			return closeOnError(fmt.Errorf("opening the attestation library: os.NewFile returned nil; closing its handle: %w", closeErr))
		}
		return closeOnError(errors.New("opening the attestation library: os.NewFile returned nil"))
	}
	verified.file = file
	verified.identity = identityFromFileInformation(info)

	canonicalPath, err := finalPathName(handle)
	if err != nil {
		return closeOnError(err)
	}
	if !filepath.IsAbs(canonicalPath) {
		return closeOnError(fmt.Errorf("%w: the canonical attestation path %q is not absolute", errDLLPathUnsafe, canonicalPath))
	}
	verified.canonicalPath = canonicalPath

	canonicalPins, err := pinPathAncestors(canonicalPath)
	if err != nil {
		return closeOnError(fmt.Errorf("pinning the canonical attestation path: %w", err))
	}
	verified.pins.handles = append(verified.pins.handles, canonicalPins.handles...)
	canonicalPins.handles = nil

	canonicalHandle, canonicalInfo, err := openPinnedPathComponent(canonicalPath, false)
	if err != nil {
		return closeOnError(fmt.Errorf("opening the canonical attestation path: %w", err))
	}
	verified.pins.handles = append(verified.pins.handles, canonicalHandle)
	if !sameFileIdentity(verified.identity, identityFromFileInformation(canonicalInfo)) {
		return closeOnError(fmt.Errorf("%w: the canonical path no longer identifies the verified attestation file", errDLLPathUnsafe))
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return closeOnError(fmt.Errorf("hashing the attestation library: %w", err))
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != expectedDLLSHA256 {
		return closeOnError(fmt.Errorf("%w: on-disk SHA-256 is %s, expected %s", errDLLIntegrity, got, expectedDLLSHA256))
	}
	if err := verifyAuthenticode(canonicalPath, handle); err != nil {
		return closeOnError(err)
	}
	return verified, nil
}

func pinPathAncestors(path string) (*pinnedHandles, error) {
	ancestors, err := pathAncestors(path)
	if err != nil {
		return nil, err
	}
	pins := &pinnedHandles{}
	for _, ancestor := range ancestors {
		handle, _, err := openPinnedPathComponent(ancestor, true)
		if err != nil {
			if closeErr := pins.close(); closeErr != nil {
				err = fmt.Errorf("%v; %w", err, closeErr)
			}
			return nil, err
		}
		pins.handles = append(pins.handles, handle)
	}
	return pins, nil
}

func prepareAndPinDirectory(directory string) (*pinnedHandles, error) {
	components, err := pathAncestors(filepath.Join(directory, "_"))
	if err != nil {
		return nil, err
	}
	pins := &pinnedHandles{}
	for i, component := range components {
		handle, _, openErr := openPinnedPathComponentForCreation(component)
		if openErr != nil && !errors.Is(openErr, windows.ERROR_FILE_NOT_FOUND) &&
			!errors.Is(openErr, windows.ERROR_PATH_NOT_FOUND) {
			return nil, pins.closeAfterError(openErr)
		}
		if openErr != nil {
			if i == 0 {
				return nil, pins.closeAfterError(openErr)
			}
			if err := os.Mkdir(component, 0700); err != nil && !errors.Is(err, os.ErrExist) {
				return nil, pins.closeAfterError(fmt.Errorf("creating directory %q: %w", component, err))
			}
			handle, _, openErr = openPinnedPathComponentForCreation(component)
			if openErr != nil {
				return nil, pins.closeAfterError(openErr)
			}
		}
		pins.handles = append(pins.handles, handle)
	}
	return pins, nil
}

func pathAncestors(path string) ([]string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return nil, fmt.Errorf("refusing to pin non-absolute attestation path %q", path)
	}
	volume, rest := splitWindowsVolume(clean)
	if volume == "" {
		return nil, fmt.Errorf("attestation path %q has no Windows volume", path)
	}
	components := strings.FieldsFunc(rest, func(r rune) bool {
		return r == '\\' || r == '/'
	})
	if len(components) == 0 {
		return nil, fmt.Errorf("attestation path %q does not name a file", path)
	}

	current := volume + `\`
	ancestors := []string{current}
	for _, component := range components[:len(components)-1] {
		current = filepath.Join(current, component)
		ancestors = append(ancestors, current)
	}
	return ancestors, nil
}

func splitWindowsVolume(path string) (volume, rest string) {
	const extendedUNC = `\\?\UNC\`
	if len(path) >= len(extendedUNC) && strings.EqualFold(path[:len(extendedUNC)], extendedUNC) {
		components := strings.FieldsFunc(path[len(extendedUNC):], func(r rune) bool {
			return r == '\\' || r == '/'
		})
		if len(components) < 2 {
			return "", path
		}
		volume = path[:len(extendedUNC)] + components[0] + `\` + components[1]
		prefixLength := len(extendedUNC) + len(components[0]) + 1 + len(components[1])
		return volume, path[prefixLength:]
	}
	volume = filepath.VolumeName(path)
	return volume, strings.TrimPrefix(path, volume)
}

func openPinnedPathComponent(path string, directory bool) (windows.Handle, windows.ByHandleFileInformation, error) {
	return openPinnedPathComponentWithWrites(path, directory, false)
}

func openPinnedPathComponentForCreation(path string) (windows.Handle, windows.ByHandleFileInformation, error) {
	return openPinnedPathComponentWithWrites(path, true, true)
}

func openPinnedPathComponentWithWrites(path string, directory, allowWrites bool) (windows.Handle, windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, info, fmt.Errorf("encoding pinned path component %q: %w", path, err)
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	share := uint32(windows.FILE_SHARE_READ)
	access := uint32(windows.FILE_READ_DATA | windows.FILE_READ_ATTRIBUTES)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
		access = windows.FILE_READ_ATTRIBUTES
		if allowWrites {
			share |= windows.FILE_SHARE_WRITE
		}
	}
	handle, err := windows.CreateFile(
		pathPtr,
		access,
		share,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		return 0, info, fmt.Errorf("opening pinned path component %q: %w", path, err)
	}
	closeOnError := func(err error) (windows.Handle, windows.ByHandleFileInformation, error) {
		if closeErr := windows.CloseHandle(handle); closeErr != nil {
			err = fmt.Errorf("%v; closing pinned path component %q: %w", err, path, closeErr)
		}
		return 0, info, err
	}

	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return closeOnError(fmt.Errorf("inspecting pinned path component %q: %w", path, err))
	}
	if err := validatePinnedPathComponent(path, info, directory); err != nil {
		return closeOnError(err)
	}
	return handle, info, nil
}

func validatePinnedPathComponent(path string, info windows.ByHandleFileInformation, directory bool) error {
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: path component %q is a reparse point", errDLLPathUnsafe, path)
	}
	isDirectory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDirectory != directory {
		kind := "file"
		if directory {
			kind = "directory"
		}
		return fmt.Errorf("%w: path component %q is not a %s", errDLLPathUnsafe, path, kind)
	}
	return nil
}

func identityFromFileInformation(info windows.ByHandleFileInformation) fileIdentity {
	return fileIdentity{
		volumeSerialNumber: info.VolumeSerialNumber,
		fileIndexHigh:      info.FileIndexHigh,
		fileIndexLow:       info.FileIndexLow,
	}
}

func sameFileIdentity(first, second fileIdentity) bool {
	return first == second
}

func finalPathName(handle windows.Handle) (string, error) {
	size := uint32(512)
	for size <= windows.MAX_LONG_PATH {
		buffer := make([]uint16, size)
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], size, 0)
		if err != nil {
			return "", fmt.Errorf("resolving the canonical attestation path: %w", err)
		}
		if length < size {
			return windows.UTF16ToString(buffer[:length]), nil
		}
		if length >= windows.MAX_LONG_PATH {
			break
		}
		size = length + 1
	}
	return "", fmt.Errorf("canonical attestation path exceeds %d UTF-16 code units", windows.MAX_LONG_PATH)
}

func loadAttestationDLL(path string) (windows.Handle, error) {
	if !filepath.IsAbs(path) {
		return 0, fmt.Errorf("refusing to load the attestation library from non-absolute path %q", path)
	}
	// The target itself is named by absolute path. Restricting dependency
	// resolution to System32 keeps CWD, PATH, the application directory, and
	// the writable extraction directory out of the DLL search.
	return windows.LoadLibraryEx(path, 0, loadLibrarySearchSystem32)
}

type winTrustFileInfo struct {
	cbStruct uint32
	filePath *uint16
	file     windows.Handle
	_        *windows.GUID
}

type winTrustData struct {
	cbStruct           uint32
	policyCallbackData uintptr
	sipClientData      uintptr
	uiChoice           uint32
	revocationChecks   uint32
	unionChoice        uint32
	fileInfo           *winTrustFileInfo
	stateAction        uint32
	stateData          windows.Handle
	urlReference       *uint16
	providerFlags      uint32
	uiContext          uint32
	signatureSettings  uintptr
}

func verifyAuthenticode(path string, handle windows.Handle) error {
	if err := winVerifyTrust.Find(); err != nil {
		return fmt.Errorf("%w: resolving WinVerifyTrust: %v", errDLLSignature, err)
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("%w: encoding path: %v", errDLLSignature, err)
	}
	fileInfo := winTrustFileInfo{
		cbStruct: uint32(unsafe.Sizeof(winTrustFileInfo{})),
		filePath: pathPtr,
		file:     handle,
	}
	data := winTrustData{
		cbStruct:         uint32(unsafe.Sizeof(winTrustData{})),
		uiChoice:         winTrustUINone,
		revocationChecks: winTrustRevokeNone,
		unionChoice:      winTrustChoiceFile,
		fileInfo:         &fileInfo,
		stateAction:      winTrustStateActionVerify,
		providerFlags:    winTrustRevocationNone | winTrustCacheOnlyURLLookup,
	}

	// The pinned SHA-256 identifies the exact Microsoft package asset. This
	// independent trust check proves its Authenticode signature and chain are
	// valid on the host before any bytes are mapped executable.
	//nolint:gosec // WinVerifyTrust requires pointers to its Windows API structures.
	status, _, _ := winVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&winTrustActionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&data)),
	)

	data.stateAction = winTrustStateActionClose
	//nolint:gosec // WinVerifyTrust requires pointers to its Windows API structures.
	closeStatus, _, _ := winVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&winTrustActionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&data)),
	)
	runtime.KeepAlive(pathPtr)
	runtime.KeepAlive(&fileInfo)
	runtime.KeepAlive(&data)

	if status != 0 {
		return fmt.Errorf("%w for %q: WinVerifyTrust returned 0x%08X", errDLLSignature, path, status)
	}
	if closeStatus != 0 {
		return fmt.Errorf("%w for %q: closing WinVerifyTrust state returned 0x%08X", errDLLSignature, path, closeStatus)
	}
	return nil
}
