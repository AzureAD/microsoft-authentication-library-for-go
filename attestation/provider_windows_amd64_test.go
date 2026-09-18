// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build windows && amd64
// +build windows,amd64

package attestation

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	managedidentity "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
	"golang.org/x/sys/windows"
)

func TestEmbeddedDLLHashAndAuthenticodeSignature(t *testing.T) {
	if err := verifyEmbeddedDLL(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(embeddedDLL)
	if got := hex.EncodeToString(sum[:]); got != expectedDLLSHA256 {
		t.Fatalf("embedded DLL SHA-256 = %s, want %s", got, expectedDLLSHA256)
	}

	temp, err := writeEmbeddedDLL(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(temp) }()
	if err := verifyDLLFile(temp); err != nil {
		t.Fatalf("verifying authentic embedded DLL: %v", err)
	}
}

func TestAttestationDLLPathIsStableVersionedAndAbsolute(t *testing.T) {
	first, err := attestationDLLPath()
	if err != nil {
		t.Fatal(err)
	}
	second, err := attestationDLLPath()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("attestation path changed between calls: %q then %q", first, second)
	}
	if !filepath.IsAbs(first) {
		t.Fatalf("attestation path %q is not absolute", first)
	}
	wantSuffix := filepath.Join("Microsoft", "MSAL", "attestation", packageVersion, "win-x64", dllName)
	if !strings.HasSuffix(first, wantSuffix) {
		t.Fatalf("attestation path %q does not end with %q", first, wantSuffix)
	}
}

func TestMaterializeLoadsAndReusesVerifiedDLL(t *testing.T) {
	path := filepath.Join(t.TempDir(), dllName)
	var loaded []string
	loader := func(path string) (windows.Handle, error) {
		loaded = append(loaded, path)
		return loadAttestationDLL(path)
	}

	handle, err := materializeAndLoad(path, loader)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.FreeLibrary(handle); err != nil {
		t.Fatalf("unloading first DLL handle: %v", err)
	}
	stamp := time.Unix(1_700_000_000, 0)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatalf("setting a reuse marker timestamp: %v", err)
	}

	handle, err = materializeAndLoad(path, loader)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.FreeLibrary(handle); err != nil {
		t.Fatalf("unloading second DLL handle: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(stamp) {
		t.Fatalf("verified DLL was rewritten on reuse: modtime = %s, want %s", info.ModTime(), stamp)
	}
	if len(loaded) != 2 {
		t.Fatalf("loader called %d times, want once for each materializeAndLoad call", len(loaded))
	}
	verified, err := openVerifiedDLL(path)
	if err != nil {
		t.Fatal(err)
	}
	canonicalPath := verified.canonicalPath
	if err := verified.close(); err != nil {
		t.Fatal(err)
	}
	for _, loadedPath := range loaded {
		if !strings.EqualFold(filepath.Clean(loadedPath), filepath.Clean(canonicalPath)) ||
			!filepath.IsAbs(loadedPath) {
			t.Fatalf("loader received %q, want canonical absolute path %q", loadedPath, canonicalPath)
		}
	}
}

func TestCorruptOnDiskDLLIsRepairedBeforeLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), dllName)
	if err := os.WriteFile(path, []byte("not the attestation library"), 0600); err != nil {
		t.Fatal(err)
	}

	handle, err := materializeAndLoad(path, loadAttestationDLL)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.FreeLibrary(handle); err != nil {
		t.Fatalf("unloading repaired DLL: %v", err)
	}
	//nolint:gosec // path is the fixed DLL name under t.TempDir.
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bytes)
	if got := hex.EncodeToString(sum[:]); got != expectedDLLSHA256 {
		t.Fatalf("repaired DLL SHA-256 = %s, want %s", got, expectedDLLSHA256)
	}
}

func TestLoadFailureFailsClosedAndReceivesAbsolutePath(t *testing.T) {
	var loadedPath string
	provider := &libraryProvider{
		path: filepath.Join(t.TempDir(), dllName),
		loader: func(path string) (windows.Handle, error) {
			loadedPath = path
			return 0, windows.ERROR_BAD_EXE_FORMAT
		},
	}

	handle, err := provider.LoadAttestationLibrary()
	if handle != 0 {
		t.Fatalf("handle = %#x, want zero", handle)
	}
	if !errors.Is(err, managedidentity.ErrAttestationUnavailable) {
		t.Fatalf("error = %v, want it to wrap ErrAttestationUnavailable", err)
	}
	if !errors.Is(err, windows.ERROR_BAD_EXE_FORMAT) {
		t.Fatalf("error = %v, want it to wrap the loader failure", err)
	}
	if !filepath.IsAbs(loadedPath) {
		t.Fatalf("loader received non-absolute path %q", loadedPath)
	}
}

func TestEmbeddedCorruptionFailsClosedBeforeWritingOrLoading(t *testing.T) {
	original := embeddedDLL[0]
	embeddedDLL[0] ^= 0xff
	defer func() { embeddedDLL[0] = original }()

	path := filepath.Join(t.TempDir(), dllName)
	loaded := false
	provider := &libraryProvider{
		path: path,
		loader: func(string) (windows.Handle, error) {
			loaded = true
			return 0, nil
		},
	}
	if _, err := provider.LoadAttestationLibrary(); !errors.Is(err, managedidentity.ErrAttestationUnavailable) {
		t.Fatalf("error = %v, want it to wrap ErrAttestationUnavailable", err)
	}
	if loaded {
		t.Fatal("loader was called for corrupt embedded bytes")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("materialized file exists after embedded hash failure: %v", err)
	}
}

func TestLoaderRejectsRelativePath(t *testing.T) {
	if _, err := loadAttestationDLL(dllName); err == nil {
		t.Fatal("relative DLL path was accepted")
	}
}

func TestVerifiedDLLPinsOrdinaryAncestryAndCanonicalIdentity(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "one", "two")
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, dllName)
	if err := os.WriteFile(path, embeddedDLL, 0600); err != nil {
		t.Fatal(err)
	}

	verified, err := openVerifiedDLL(path)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(verified.canonicalPath) {
		t.Fatalf("canonical path %q is not absolute", verified.canonicalPath)
	}
	canonicalHandle, canonicalInfo, err := openPinnedPathComponent(verified.canonicalPath, false)
	if err != nil {
		_ = verified.close()
		t.Fatal(err)
	}
	if err := windows.CloseHandle(canonicalHandle); err != nil {
		_ = verified.close()
		t.Fatal(err)
	}
	if !sameFileIdentity(verified.identity, identityFromFileInformation(canonicalInfo)) {
		_ = verified.close()
		t.Fatal("canonical path does not identify the verified file")
	}

	renamed := parent + "-renamed"
	if err := os.Rename(parent, renamed); err == nil {
		_ = os.Rename(renamed, parent)
		_ = verified.close()
		t.Fatal("an ancestor was renamed while its pin was held")
	}
	if err := verified.close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(parent, renamed); err != nil {
		t.Fatalf("ancestor remained pinned after cleanup: %v", err)
	}
	if err := os.Rename(renamed, parent); err != nil {
		t.Fatalf("restoring renamed test directory: %v", err)
	}
}

func TestReparsePointAncestorIsRejected(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
			t.Skipf("creating a directory reparse point requires privilege: %v", err)
		}
		t.Fatalf("creating directory reparse point: %v", err)
	}
	path := filepath.Join(target, dllName)
	if err := os.WriteFile(path, embeddedDLL, 0600); err != nil {
		t.Fatal(err)
	}

	_, err := openVerifiedDLL(filepath.Join(link, dllName))
	if !errors.Is(err, errDLLPathUnsafe) || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("error = %v, want unsafe reparse-point rejection", err)
	}

	loaderCalled := false
	_, err = materializeAndLoad(filepath.Join(link, "new", dllName), func(string) (windows.Handle, error) {
		loaderCalled = true
		return 0, errors.New("unexpected loader call")
	})
	if !errors.Is(err, errDLLPathUnsafe) {
		t.Fatalf("materializeAndLoad error = %v, want unsafe-path rejection", err)
	}
	if loaderCalled {
		t.Fatal("loader was called through a reparse-point ancestor")
	}
	if _, err := os.Stat(filepath.Join(target, "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe directory creation traversed the reparse point: %v", err)
	}
}

func TestFinalReparsePointIsRejectedWithoutRepair(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, dllName)
	if err := os.Symlink(filepath.Join(root, "missing-target"), path); err != nil {
		if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
			t.Skipf("creating a file reparse point requires privilege: %v", err)
		}
		t.Fatalf("creating file reparse point: %v", err)
	}

	loaderCalled := false
	_, err := materializeAndLoad(path, func(string) (windows.Handle, error) {
		loaderCalled = true
		return 0, errors.New("unexpected loader call")
	})
	if !errors.Is(err, errDLLPathUnsafe) {
		t.Fatalf("error = %v, want unsafe-path rejection", err)
	}
	if loaderCalled {
		t.Fatal("loader was called for a final reparse point")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("unsafe final path was removed or replaced: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("unsafe final path mode = %v, want symlink", info.Mode())
	}
}

func TestReparsePointValidationSeamRejectsAncestry(t *testing.T) {
	info := windows.ByHandleFileInformation{
		FileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_REPARSE_POINT,
	}
	err := validatePinnedPathComponent(`C:\safe\junction`, info, true)
	if !errors.Is(err, errDLLPathUnsafe) || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("error = %v, want deterministic reparse-point rejection", err)
	}
}

func TestPathAncestorsSupportsWindowsAbsoluteForms(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
		want []string
	}{
		{
			name: "drive",
			path: `C:\Users\person\AppData\Local\library.dll`,
			want: []string{`C:\`, `C:\Users`, `C:\Users\person`, `C:\Users\person\AppData`, `C:\Users\person\AppData\Local`},
		},
		{
			name: "UNC",
			path: `\\server\share\person\library.dll`,
			want: []string{`\\server\share\`, `\\server\share\person`},
		},
		{
			name: "extended UNC",
			path: `\\?\UNC\server\share\person\library.dll`,
			want: []string{`\\?\UNC\server\share\`, `\\?\UNC\server\share\person`},
		},
		{
			name: "volume GUID",
			path: `\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\person\library.dll`,
			want: []string{
				`\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\`,
				`\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\person`,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := pathAncestors(test.path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, "|") != strings.Join(test.want, "|") {
				t.Fatalf("pathAncestors(%q) = %#v, want %#v", test.path, got, test.want)
			}
		})
	}
}

func TestFileIdentityComparisonRejectsAnyMismatch(t *testing.T) {
	base := fileIdentity{volumeSerialNumber: 1, fileIndexHigh: 2, fileIndexLow: 3}
	if !sameFileIdentity(base, base) {
		t.Fatal("identical file identities did not match")
	}
	for _, different := range []fileIdentity{
		{volumeSerialNumber: 9, fileIndexHigh: 2, fileIndexLow: 3},
		{volumeSerialNumber: 1, fileIndexHigh: 9, fileIndexLow: 3},
		{volumeSerialNumber: 1, fileIndexHigh: 2, fileIndexLow: 9},
	} {
		if sameFileIdentity(base, different) {
			t.Fatalf("different identities matched: %#v and %#v", base, different)
		}
	}
}

const (
	helperModeEnv = "MSAL_ATTESTATION_TEST_HELPER_MODE"
	helperPathEnv = "MSAL_ATTESTATION_TEST_HELPER_PATH"
)

func TestExtractionLockHelperProcess(t *testing.T) {
	mode := os.Getenv(helperModeEnv)
	if mode == "" {
		return
	}
	path := os.Getenv(helperPathEnv)
	if path == "" {
		t.Fatal("helper path is empty")
	}

	switch mode {
	case "hold":
		lock, err := acquireExtractionLock(path)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("HELPER_LOCKED")
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			_ = lock.release()
			t.Fatal(err)
		}
		if err := lock.release(); err != nil {
			t.Fatal(err)
		}
		fmt.Println("HELPER_RELEASED")
	case "load":
		fmt.Println("HELPER_STARTED")
		var contention sync.Once
		defaultExtractionLockPolicy.onContention = func() {
			contention.Do(func() { fmt.Println("HELPER_CONTENDED") })
		}
		var loadedPath string
		handle, err := materializeAndLoad(path, func(path string) (windows.Handle, error) {
			loadedPath = path
			return loadAttestationDLL(path)
		})
		if err != nil {
			t.Fatal(err)
		}
		if handle == 0 || !filepath.IsAbs(loadedPath) {
			t.Fatalf("loaded handle/path = %#x/%q", handle, loadedPath)
		}
		if err := windows.FreeLibrary(handle); err != nil {
			t.Fatal(err)
		}
		verified, err := openVerifiedDLL(path)
		if err != nil {
			t.Fatal(err)
		}
		canonicalPath := verified.canonicalPath
		if err := verified.close(); err != nil {
			t.Fatal(err)
		}
		if !strings.EqualFold(filepath.Clean(loadedPath), filepath.Clean(canonicalPath)) {
			t.Fatalf("loaded path = %q, want canonical verified path %q", loadedPath, canonicalPath)
		}
		fmt.Println("HELPER_LOADED")
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}

type helperProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  <-chan string
	stderr bytes.Buffer
	waited bool
}

func startHelperProcess(t *testing.T, mode, path, ready string) *helperProcess {
	t.Helper()
	//nolint:gosec // The executable and test selector are fixed; mode/path are passed through the environment.
	cmd := exec.Command(os.Args[0], "-test.run=^TestExtractionLockHelperProcess$")
	cmd.Env = append(os.Environ(), helperModeEnv+"="+mode, helperPathEnv+"="+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	process := &helperProcess{cmd: cmd, stdin: stdin}
	cmd.Stderr = &process.stderr
	lines := make(chan string, 128)
	process.lines = lines
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	t.Cleanup(func() {
		if !process.waited && process.cmd.Process != nil {
			_ = process.cmd.Process.Kill()
			_ = process.cmd.Wait()
			process.waited = true
		}
	})
	process.waitForLine(t, ready)
	return process
}

func (p *helperProcess) waitForLine(t *testing.T, marker string) {
	t.Helper()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		select {
		case line, ok := <-p.lines:
			if !ok {
				err := p.wait()
				t.Fatalf("helper exited before %q: %v\nstderr:\n%s", marker, err, p.stderr.String())
			}
			if strings.Contains(line, marker) {
				return
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for helper marker %q", marker)
		}
	}
}

func (p *helperProcess) wait() error {
	if p.waited {
		return nil
	}
	if p.stdin != nil {
		_ = p.stdin.Close()
		p.stdin = nil
	}
	p.waited = true
	return p.cmd.Wait()
}

func (p *helperProcess) release(t *testing.T) {
	t.Helper()
	if p.stdin != nil {
		if err := p.stdin.Close(); err != nil {
			t.Fatal(err)
		}
		p.stdin = nil
	}
	p.waitForLine(t, "HELPER_RELEASED")
	if err := p.wait(); err != nil {
		t.Fatalf("lock holder failed: %v\nstderr:\n%s", err, p.stderr.String())
	}
}

func TestConcurrentProcessesPublishAndLoadOneVerifiedDLL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, dllName)
	holder := startHelperProcess(t, "hold", path+".lock", "HELPER_LOCKED")

	const contenders = 3
	workers := make([]*helperProcess, contenders)
	for i := range workers {
		workers[i] = startHelperProcess(t, "load", path, "HELPER_CONTENDED")
	}
	holder.release(t)
	for i, worker := range workers {
		worker.waitForLine(t, "HELPER_LOADED")
		if err := worker.wait(); err != nil {
			t.Fatalf("contender %d failed: %v\nstderr:\n%s", i, err, worker.stderr.String())
		}
	}

	if err := verifyDLLFile(path); err != nil {
		t.Fatalf("final published DLL is not verified: %v", err)
	}
	temporary, err := filepath.Glob(filepath.Join(dir, ".AttestationClientLib-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temporary) != 0 {
		t.Fatalf("temporary extraction files remain: %v", temporary)
	}
	lock, err := acquireExtractionLock(path + ".lock")
	if err != nil {
		t.Fatalf("a contender left the extraction lock held: %v", err)
	}
	if err := lock.release(); err != nil {
		t.Fatal(err)
	}
}

func TestExtractionLockEventuallyAcquiresWithoutSleeping(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eventual.lock")
	holder := startHelperProcess(t, "hold", path, "HELPER_LOCKED")
	now := time.Unix(1_700_000_000, 0)
	waits := 0
	policy := extractionLockPolicy{
		timeout:      time.Second,
		initialRetry: time.Millisecond,
		maximumRetry: time.Millisecond,
		now:          func() time.Time { return now },
		wait: func(delay time.Duration) {
			waits++
			holder.release(t)
			now = now.Add(delay)
		},
	}
	lock, err := acquireExtractionLockWithPolicy(path, policy)
	if err != nil {
		t.Fatal(err)
	}
	if waits != 1 {
		t.Fatalf("waited %d times, want exactly one deterministic contention", waits)
	}
	if err := lock.release(); err != nil {
		t.Fatal(err)
	}
}

func TestExtractionLockTimeoutIsBoundedAndClosesHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "timeout.lock")
	holder := startHelperProcess(t, "hold", path, "HELPER_LOCKED")
	now := time.Unix(1_700_000_000, 0)
	policy := extractionLockPolicy{
		timeout:      25 * time.Millisecond,
		initialRetry: 10 * time.Millisecond,
		maximumRetry: 10 * time.Millisecond,
		now:          func() time.Time { return now },
		wait:         func(delay time.Duration) { now = now.Add(delay) },
	}
	lock, err := acquireExtractionLockWithPolicy(path, policy)
	if lock != nil {
		_ = lock.release()
		t.Fatal("acquired a lock held by another process")
	}
	if !errors.Is(err, managedidentity.ErrAttestationUnavailable) ||
		!errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
		!strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error = %v, want bounded unavailable lock timeout", err)
	}
	holder.release(t)
	if err := os.Remove(path); err != nil {
		t.Fatalf("lock handle remained open after timeout: %v", err)
	}
}
