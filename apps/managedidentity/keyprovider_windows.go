// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build windows

package managedidentity

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This file creates the key IMDSv2 binds a token to. Unlike the signer in
// apps/tests/devapps/keyguard/ncryptsigner, which adopts the key behind a
// certificate that already exists in a Windows store, IMDSv2 has to mint a key
// first and only afterwards receives a certificate for it. That is why key
// creation lives here rather than being borrowed from that sample.
//
// Every NCrypt entry point that takes a pointer is invoked through
// syscall.SyscallN rather than LazyProc.Call. Converting unsafe.Pointer to
// uintptr is only defined when the conversion appears in the argument list of
// an assembly-implemented call; LazyProc.Call is ordinary Go, so the operands
// would be spilled into a variadic []uintptr and carried across further Go
// calls, any of which can grow -- and therefore move -- the stack while only a
// bare integer refers to the object.

var (
	ncryptDLL = windows.NewLazySystemDLL("ncrypt.dll")

	procNCryptOpenStorageProvider = ncryptDLL.NewProc("NCryptOpenStorageProvider")
	procNCryptOpenKey             = ncryptDLL.NewProc("NCryptOpenKey")
	procNCryptCreatePersistedKey  = ncryptDLL.NewProc("NCryptCreatePersistedKey")
	procNCryptSetProperty         = ncryptDLL.NewProc("NCryptSetProperty")
	procNCryptGetProperty         = ncryptDLL.NewProc("NCryptGetProperty")
	procNCryptFinalizeKey         = ncryptDLL.NewProc("NCryptFinalizeKey")
	procNCryptDeleteKey           = ncryptDLL.NewProc("NCryptDeleteKey")
	procNCryptExportKey           = ncryptDLL.NewProc("NCryptExportKey")
	procNCryptSignHash            = ncryptDLL.NewProc("NCryptSignHash")
	procNCryptFreeObject          = ncryptDLL.NewProc("NCryptFreeObject")
)

const (
	// msKeyStorageProvider is MS_KEY_STORAGE_PROVIDER, the software KSP. It is
	// the provider that implements VBS isolation; the platform TPM provider does
	// not offer the virtual isolation flag.
	msKeyStorageProvider = "Microsoft Software Key Storage Provider"

	ncryptRSAAlgorithm = "RSA"

	ncryptLengthProperty       = "Length"
	ncryptExportPolicyProperty = "Export Policy"
	// ncryptKeyUsageProperty is NCRYPT_KEY_USAGE_PROPERTY.
	ncryptKeyUsageProperty = "Key Usage"
	// ncryptAllowAllUsages is NCRYPT_ALLOW_ALL_USAGES. MSAL .NET sets it when
	// it creates the KeyGuard key (CngKeyCreationParameters.KeyUsage =
	// AllUsages). Without it the key takes the KSP's default usage mask, which
	// can refuse the signature the CSR needs on hosts whose policy narrows that
	// default.
	ncryptAllowAllUsages = 0x00ffffff
	// ncryptVirtualIsoProperty is NCRYPT_VIRTUAL_ISO_PROPERTY. CNG sets it to 1
	// for keys whose private material is held by the VBS trustlet, which is what
	// "KeyGuard" means in practice.
	ncryptVirtualIsoProperty = "Virtual Iso"

	// ncryptUseVirtualIsolationFlag is NCRYPT_USE_VIRTUAL_ISOLATION_FLAG. It
	// asks the KSP to place the private key inside the VBS trustlet.
	ncryptUseVirtualIsolationFlag = 0x00020000
	// ncryptUsePerBootKeyFlag is NCRYPT_USE_PER_BOOT_KEY_FLAG. It ties the
	// isolated key to the current boot, so it cannot survive a reboot and be
	// replayed afterwards. The flag is reflected in the isolated key attributes
	// that the attestation statement carries, and IMDS requires it, so a key
	// created without it attests successfully but is refused a credential.
	ncryptUsePerBootKeyFlag = 0x00040000
	ncryptSilentFlag        = 0x00000040

	// bcryptPadPSSFlag is BCRYPT_PAD_PSS.
	bcryptPadPSSFlag = 0x00000008
	// bcryptPadPKCS1Flag is BCRYPT_PAD_PKCS1.
	bcryptPadPKCS1Flag = 0x00000002

	// nteExists is NTE_EXISTS, returned when the named key is already present.
	nteExists = 0x8009000F
	// nteBadKeyset is NTE_BAD_KEYSET, one of the codes NCryptOpenKey uses for a
	// key that does not exist.
	nteBadKeyset = 0x80090016
	// nteNoKey is NTE_NO_KEY.
	nteNoKey = 0x8009000D
	// nteNotFoundStatus is NTE_NOT_FOUND.
	nteNotFoundStatus = 0x80090011
	// nteNotSupported is NTE_NOT_SUPPORTED, returned by NCryptGetProperty for a
	// property the provider does not implement.
	nteNotSupported = 0x80090029

	// rsaPublicBlob is BCRYPT_RSAPUBLIC_BLOB, the only blob type a VBS-isolated
	// key exports. CNG refuses every blob that would carry private material.
	rsaPublicBlob = "RSAPUBLICBLOB"
	// bcryptRSAPublicMagicValue is BCRYPT_RSAPUBLIC_MAGIC; it reads "RSA1".
	bcryptRSAPublicMagicValue = 0x31415352
	// rsaBlobHeaderLen is sizeof(BCRYPT_RSAKEY_BLOB).
	rsaBlobHeaderLen = 24
)

// bcryptPSSPaddingInfo is BCRYPT_PSS_PADDING_INFO.
type bcryptPSSPaddingInfo struct {
	pszAlgID *uint16
	cbSalt   uint32
}

// bcryptPKCS1PaddingInfo is BCRYPT_PKCS1_PADDING_INFO.
type bcryptPKCS1PaddingInfo struct {
	pszAlgID *uint16
}

// statusCode narrows a SECURITY_STATUS returned through the syscall ABI. CNG
// defines SECURITY_STATUS as a 32-bit value, but syscall.SyscallN widens every
// return into a uintptr, so the upper half on 64-bit Windows is padding rather
// than part of the status. Narrowing happens here once so the truncation is
// audited in a single place instead of at each comparison.
//
// #nosec G115 -- see above: the value is 32-bit by contract, so this cannot lose
// information.
func statusCode(status uintptr) uint32 { return uint32(status) }

func ncryptStatusError(op string, status uintptr) error {
	return fmt.Errorf("managedidentity: %s failed: %w (0x%08X)", op, windows.Errno(status), statusCode(status))
}

// keyGuardProvider creates and opens VBS-isolated RSA keys.
type keyGuardProvider struct{}

// openProvider opens the software KSP.
func openProvider() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(msKeyStorageProvider)
	if err != nil {
		return 0, fmt.Errorf("managedidentity: encoding the provider name: %w", err)
	}
	var provider windows.Handle
	status, _, _ := syscall.SyscallN(procNCryptOpenStorageProvider.Addr(),
		uintptr(unsafe.Pointer(&provider)),
		uintptr(unsafe.Pointer(name)),
		0,
	)
	if status != 0 {
		return 0, ncryptStatusError("NCryptOpenStorageProvider", status)
	}
	return provider, nil
}

func freeNCryptObject(h windows.Handle) {
	if h != 0 {
		_, _, _ = syscall.SyscallN(procNCryptFreeObject.Addr(), uintptr(h))
	}
}

// isNotFound reports whether a SECURITY_STATUS means "no such key".
func isNotFound(status uintptr) bool {
	switch statusCode(status) {
	case nteBadKeyset, nteNoKey, nteNotFoundStatus:
		return true
	}
	return false
}

// openExistingKey opens a persisted key by name, reporting whether it existed.
func openExistingKey(provider windows.Handle, name *uint16) (windows.Handle, bool, error) {
	var key windows.Handle
	status, _, _ := syscall.SyscallN(procNCryptOpenKey.Addr(),
		uintptr(provider),
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(name)),
		0,
		uintptr(ncryptSilentFlag),
	)
	switch {
	case status == 0:
		return key, true, nil
	case isNotFound(status):
		return 0, false, nil
	default:
		return 0, false, ncryptStatusError("NCryptOpenKey", status)
	}
}

// setDWORDProperty sets a DWORD-valued property on a CNG object.
func setDWORDProperty(h windows.Handle, property string, value uint32) error {
	name, err := windows.UTF16PtrFromString(property)
	if err != nil {
		return fmt.Errorf("managedidentity: encoding the property name: %w", err)
	}
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, value)
	status, _, _ := syscall.SyscallN(procNCryptSetProperty.Addr(),
		uintptr(h),
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(ncryptSilentFlag),
	)
	if status != 0 {
		return ncryptStatusError("NCryptSetProperty("+property+")", status)
	}
	return nil
}

// getDWORDProperty reads a DWORD-valued property. A property the provider does
// not implement is reported as absent rather than as a failure.
func getDWORDProperty(h windows.Handle, property string) (uint32, bool, error) {
	name, err := windows.UTF16PtrFromString(property)
	if err != nil {
		return 0, false, fmt.Errorf("managedidentity: encoding the property name: %w", err)
	}
	var buf [4]byte
	var written uint32
	status, _, _ := syscall.SyscallN(procNCryptGetProperty.Addr(),
		uintptr(h),
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&written)),
		uintptr(ncryptSilentFlag),
	)
	if status != 0 {
		if isNotFound(status) || statusCode(status) == nteNotSupported {
			return 0, false, nil
		}
		return 0, false, ncryptStatusError("NCryptGetProperty("+property+")", status)
	}
	if written < 4 {
		return 0, false, nil
	}
	return binary.LittleEndian.Uint32(buf[:]), true, nil
}

// bindingKeyCreateFlags is what NCryptCreatePersistedKey is called with when the
// name is expected to be free.
//
// NCRYPT_OVERWRITE_KEY_FLAG is absent here so that a create which races another
// process loses cleanly with NTE_EXISTS and adopts the winner, rather than
// destroying a key somebody is already using. It is added back, and only added
// back, when recovering a key this caller has just observed to be unusable - see
// bindingKeyReplaceFlags and resolveBindingKey.
//
// The flags are a named constant rather than an expression inlined at the call
// site so the absence is checkable. See TestBindingKeyCreateFlagsDoNotOverwrite.
const bindingKeyCreateFlags = ncryptUseVirtualIsolationFlag | ncryptUsePerBootKeyFlag

// ncryptOverwriteKeyFlag is NCRYPT_OVERWRITE_KEY_FLAG.
const ncryptOverwriteKeyFlag = 0x00000080

// bindingKeyReplaceFlags recreates the key over a name that already exists.
//
// This is the flag set MSAL .NET always uses - CreateFresh passes
// OverwriteExistingKey together with the virtual-isolation and per-boot flags -
// and it is required on the recovery path: the stale name is still there, so a
// create without overwrite returns NTE_EXISTS for ever, and the alternative of
// deleting the name through the stale handle is the operation that destroys
// another process's replacement. See resolveBindingKey.
const bindingKeyReplaceFlags = bindingKeyCreateFlags | ncryptOverwriteKeyFlag

// errBindingKeyExists reports that this process lost the race to create the
// named key: somebody else has it. It is a signal to adopt the winner, not a
// failure.
var errBindingKeyExists = errors.New("managedidentity: the binding key already exists")

// bindingKeyCreateError maps an NCrypt status from key creation or
// finalization into the error resolveBindingKey acts on.
//
// NTE_EXISTS means the same thing from either call: somebody else holds the
// name. It arrives from NCryptCreatePersistedKey when the rival finalized before
// this process created, and it can arrive from NCryptFinalizeKey instead,
// because finalization is where the key is actually written and a provider is
// free to report the collision there. Both are a lost race rather than a broken
// host, so both map to errBindingKeyExists and the caller adopts the winner.
func bindingKeyCreateError(op string, status uintptr) error {
	if statusCode(status) == nteExists {
		return errBindingKeyExists
	}
	// A host without VBS rejects the virtual isolation flag outright.
	return fmt.Errorf("%w: %v", ErrCredentialGuardNotAvailable, ncryptStatusError(op, status))
}

// createPersistedKey mints a VBS-isolated RSA key called name.
//
// overwrite selects bindingKeyReplaceFlags, which replaces whatever is under the
// name. Only the recovery path in resolveBindingKey passes it, and only after
// observing that the persisted key cannot sign; everything else creates without
// it so a lost race is reported as NTE_EXISTS instead of destroying a live key.
//
// Creation is not atomic against another process either way, and this is the
// single most important thing to understand about this function.
// NCryptCreatePersistedKey does not persist anything: it builds an in-memory key
// object, and the name is only written when NCryptFinalizeKey succeeds. Two
// processes can therefore both create, because neither has written the name yet
// and so neither is told NTE_EXISTS, and then both finalize successfully, with
// the Microsoft Software KSP letting the later finalize silently replace the
// earlier one. The observed sequence is: createA ok, createB ok, finalizeA ok,
// finalizeB ok, and the persisted key is B - while A holds a perfectly valid
// handle to a key that is no longer under the name.
//
// Nothing available here closes that window at the API level. What closes it is
// checking afterwards: resolveBindingKey reopens the name and compares public
// keys, and a caller that was replaced discards its candidate and adopts the
// persisted winner.
func createPersistedKey(provider windows.Handle, name *uint16, overwrite bool) (windows.Handle, error) {
	algorithm, err := windows.UTF16PtrFromString(ncryptRSAAlgorithm)
	if err != nil {
		return 0, fmt.Errorf("managedidentity: encoding the algorithm name: %w", err)
	}
	flags := bindingKeyCreateFlags
	if overwrite {
		flags = bindingKeyReplaceFlags
	}
	var key windows.Handle
	status, _, _ := syscall.SyscallN(procNCryptCreatePersistedKey.Addr(),
		uintptr(provider),
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(algorithm)),
		uintptr(unsafe.Pointer(name)),
		0,
		uintptr(flags),
	)
	if status != 0 {
		return 0, bindingKeyCreateError("NCryptCreatePersistedKey", status)
	}

	if err := setDWORDProperty(key, ncryptLengthProperty, csrKeyBits); err != nil {
		freeNCryptObject(key)
		return 0, err
	}
	// Export Policy 0 means the private key can never be exported. A KeyGuard
	// key already refuses to leave the trustlet; setting the policy makes the
	// intent explicit and keeps the key non-exportable if it is ever created on
	// a host that silently declines isolation.
	if err := setDWORDProperty(key, ncryptExportPolicyProperty, 0); err != nil {
		freeNCryptObject(key)
		return 0, err
	}
	// MSAL .NET sets KeyUsage = AllUsages on the KeyGuard key it creates
	// (CngKeyCreationParameters). Left unset, the key takes the KSP's default
	// usage mask, so a host whose policy narrows that default would refuse the
	// CSR signature on a key this library had already reported as usable.
	if err := setDWORDProperty(key, ncryptKeyUsageProperty, ncryptAllowAllUsages); err != nil {
		freeNCryptObject(key)
		return 0, err
	}
	// Finalization is where the name is written, so it is where a collision can
	// surface even though the create succeeded.
	status, _, _ = syscall.SyscallN(procNCryptFinalizeKey.Addr(), uintptr(key), uintptr(ncryptSilentFlag))
	if status != 0 {
		freeNCryptObject(key)
		return 0, bindingKeyCreateError("NCryptFinalizeKey", status)
	}
	return key, nil
}

// bindingKeyLockTimeout is how long provisioning waits for the cross-process key
// lock before going ahead without it.
//
// It is longer than the certificate store's persistLockTimeout because the work
// it guards is longer - creating a VBS key is a trustlet round trip, not a store
// write - and because giving up here is not free: an unlocked run may create a
// key that is then discarded, which costs a second key creation. It is still
// bounded, because a caller must not be held indefinitely behind a process that
// is wedged or a mutex some other principal is squatting on.
//
// It is a variable so a test can shorten it and observe the fail-open path
// without waiting out the real timeout.
var bindingKeyLockTimeout = 10 * time.Second

// bindingKeyLockSuffix derives a mutex name from the key container name.
//
// The scheme is deliberately the one aliasLockSuffix already uses for the
// certificate store - SHA-256 of the upper-cased value, hex, truncated - so this
// package has one convention rather than two. The prefix differs so the key lock
// and the store lock are distinct objects: they guard different resources and
// nesting them would be a deadlock waiting to happen.
//
// The name is derived from the container, so two different containers take two
// different locks and provisioning for one identity never blocks another. In
// practice every identity shares bindingKeyName, which is the point: it is one
// key, and one lock is what serializes the processes contending for it.
func bindingKeyLockSuffix(container string) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(container))))
	return "MSAL_MI_K_" + hex.EncodeToString(sum[:])[:32]
}

// bindingKeyLockNamespaces are the kernel object namespaces tried, in order.
//
// Global first so the scope matches the resource; Local as the fallback when
// creating a global object is denied. It is a variable so a test can substitute
// namespaces no object can be created in and prove that provisioning still runs
// when no lock is available at all.
var bindingKeyLockNamespaces = []string{`Global\`, `Local\`}

// withBindingKeyLock runs fn under a mutex shared by every process using this
// package that provisions the named key container.
//
// Global is tried first so the scope matches the resource: CNG CurrentUser keys
// live in the user's profile and are shared by every session that user has, so a
// session-local lock would miss a service running alongside an interactive
// logon. Creating a global object needs a privilege that is not always granted,
// and when it is refused the lock falls back to the session-local namespace,
// because deduplicating within the session is worth more than not locking at
// all. That is the same fallback withAliasLock makes, for the same reason.
//
// Unlike the store lock, a busy or unavailable lock here does not skip the work.
// Provisioning has to go ahead: refusing to mint a binding key because a mutex
// could not be taken would turn a hardening measure into a token outage. This is
// safe precisely because the lock is not what makes the result correct -
// resolveBindingKey's persisted-winner check is - so losing the lock costs a
// wasted key creation, not a wrong answer.
//
// What this lock does NOT do is exclude MSAL .NET. It is a convention private to
// this package, and .NET takes no equivalent lock when it provisions the same
// container, so a Go process and a .NET process can still both be inside their
// create-finalize sequence at once. Closing that would require both libraries to
// agree on a mutex name; until they do, the persisted-winner check is what keeps
// this library correct in that case.
func withBindingKeyLock(container string, fn func()) {
	suffix := bindingKeyLockSuffix(container)
	for _, namespace := range bindingKeyLockNamespaces {
		handle, ok := openBindingKeyLock(namespace + suffix)
		if !ok {
			// The namespace is unavailable to this process, typically because
			// creating a global object was denied. Try the next one.
			continue
		}
		runUnderBindingKeyLock(handle, fn)
		return
	}
	// No named object could be created in any namespace. Provision anyway;
	// see above.
	fn()
}

// openBindingKeyLock creates or opens the named mutex, reporting whether a
// usable handle was obtained.
//
// CreateMutex reports ERROR_ALREADY_EXISTS alongside a valid handle when the
// object was opened rather than created, which is the ordinary case and not a
// failure, so the handle rather than the error decides the outcome.
func openBindingKeyLock(name string) (windows.Handle, bool) {
	encoded, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, false
	}
	// CreateMutex reports ERROR_ALREADY_EXISTS alongside a valid handle when the
	// object was opened rather than created, which is the ordinary case here and
	// not a failure. The handle therefore decides the outcome and the error is
	// deliberately discarded.
	handle, _ := windows.CreateMutex(nil, false, encoded)
	if handle == 0 {
		return 0, false
	}
	return handle, true
}

// runUnderBindingKeyLock waits for handle, runs fn, and releases and closes on
// every path.
//
// The wait, the work and the release run on one pinned OS thread; see
// awaitNamedMutex, which both named-mutex callers in this package share. When
// ownership cannot be taken, fn runs unlocked here rather than inside
// awaitNamedMutex, so it runs exactly once either way.
func runUnderBindingKeyLock(handle windows.Handle, fn func()) {
	// Registered before the wait so it runs after the release and the unpin.
	defer func() { _ = windows.CloseHandle(handle) }()

	if awaitNamedMutex(handle, bindingKeyLockTimeout, fn) {
		return
	}
	// The lock was busy or the wait failed. Provisioning still goes ahead: the
	// persisted-winner check in resolveBindingKey is what makes the result
	// correct, so losing the lock costs a wasted key creation rather than a
	// wrong answer.
	fn()
}

// keyCanSign reports whether an opened key can still perform a private-key
// operation. A per-boot KeyGuard key leaves its metadata on disk when the
// machine reboots, so the key opens and still reports "Virtual Iso", but the
// isolated material behind it is gone. Only attempting to use it tells the
// difference, and doing so here turns a confusing failure during the TLS
// handshake into a clean re-mint.
//
// The probe uses PSS-SHA256 with a hash-length salt because that is exactly
// what the CSR signature uses. Probing with a padding the real work does not
// use would let a key that CNG will only sign PKCS1 with pass here and fail at
// the CSR, which is the failure this function exists to prevent.
func keyCanSign(key windows.Handle) bool {
	algID, err := algorithmIdentifier(crypto.SHA256)
	if err != nil {
		return false
	}
	digest := make([]byte, crypto.SHA256.Size())
	// #nosec G115 -- crypto.SHA256.Size() is the constant 32, so the conversion
	// cannot overflow uint32.
	padInfo := bcryptPSSPaddingInfo{pszAlgID: algID, cbSalt: uint32(crypto.SHA256.Size())}
	defer runtime.KeepAlive(algID)
	defer runtime.KeepAlive(&padInfo)

	var needed uint32
	status, _, _ := syscall.SyscallN(procNCryptSignHash.Addr(),
		uintptr(key), uintptr(unsafe.Pointer(&padInfo)),
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		0, 0, uintptr(unsafe.Pointer(&needed)), bcryptPadPSSFlag|ncryptSilentFlag,
	)
	if status != 0 || needed == 0 {
		return false
	}
	// The call above only asks how large a signature would be, which CNG answers
	// from the key's public metadata. That metadata is exactly what survives the
	// reboot, so the size query alone cannot distinguish a live key from a
	// stranded one. Producing a real signature is what exercises the isolated
	// private material.
	signature := make([]byte, needed)
	status, _, _ = syscall.SyscallN(procNCryptSignHash.Addr(),
		uintptr(key), uintptr(unsafe.Pointer(&padInfo)),
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&signature[0])), uintptr(len(signature)),
		uintptr(unsafe.Pointer(&needed)), bcryptPadPSSFlag|ncryptSilentFlag,
	)
	return status == 0
}

// bindingKeyGates serializes provisioning of a CNG container within this
// process.
//
// The container is process-wide - one name, shared by every identity - while
// bindingCertCache's gate is keyed by identity and attestation mode. Two
// identities therefore take different certificate gates and would provision the
// same container concurrently, each paying for a create the other's would
// discard. This gate collapses that to one.
//
// It is the cheapest of three layers and the narrowest. It covers only this
// process; withBindingKeyLock extends coordination to other processes using this
// package; and neither is the correctness boundary, which is the
// persisted-winner check in resolveBindingKey. Nothing here relies on holding
// the mutex to stay correct.
//
// A plain mutex is right here where the attestation gate is a cancellable
// channel: everything under this lock is a local CNG call, so the wait is
// bounded by the trustlet rather than by a network round trip.
var bindingKeyGates = struct {
	mu    sync.Mutex
	gates map[string]*sync.Mutex
}{gates: map[string]*sync.Mutex{}}

func bindingKeyGate(name string) *sync.Mutex {
	bindingKeyGates.mu.Lock()
	defer bindingKeyGates.mu.Unlock()
	gate, ok := bindingKeyGates.gates[name]
	if !ok {
		gate = &sync.Mutex{}
		bindingKeyGates.gates[name] = gate
	}
	return gate
}

// bindingKeyCreateAttempts bounds the open-then-create loop. Every extra pass is
// driven by another process winning a race this one just lost, which cannot
// repeat indefinitely without that other process also deleting the key it just
// created. Three passes turn a pathological loop into a clear error.
const bindingKeyCreateAttempts = 3

// bindingKeyContainer is the small set of operations resolveBindingKey drives.
//
// It exists as a seam. The loop below is the part of this file that has to get
// the cross-process race right, and its two most important branches - losing the
// create to another process and then adopting that process's key, and giving up
// after losing repeatedly - cannot be reached on demand through the public entry
// point. getOrCreateKey takes bindingKeyGate first, so goroutines in this
// process are serialized and only one of them ever reaches the create at all; a
// test driving them can only ever observe the winner. Nor can a test make real
// CNG return NTE_EXISTS on cue, since that requires a second process creating
// the key inside a window this process does not control.
//
// Putting the loop behind this interface lets those branches be exercised
// directly, below the mutex, while production still runs the identical code over
// the real CNG calls.
type bindingKeyContainer interface {
	// open reports the existing key, with ok false when there is none.
	open() (windows.Handle, bool, error)
	// usable reports whether an opened key can still perform a private-key
	// operation.
	usable(windows.Handle) bool
	// create makes the key, returning errBindingKeyExists when somebody else
	// created it first.
	//
	// overwrite replaces whatever is under the name instead of failing on it.
	// It is passed only when this caller has just observed the persisted key to
	// be unusable, because the name then already exists and a non-overwriting
	// create can never succeed against it.
	create(overwrite bool) (windows.Handle, error)
	// persisted reports whether candidate is the key the name now resolves to.
	//
	// It is the check that makes creation correct, because create alone cannot
	// be: NCryptCreatePersistedKey does not write the name, NCryptFinalizeKey
	// does, so two processes can both create and both finalize and the later
	// finalize silently replaces the earlier. Only reopening the name and
	// comparing tells a creator whether it is still the one under it.
	persisted(candidate windows.Handle) (bool, error)
	// discard releases a handle without deleting the key behind it.
	//
	// This is how a stale handle is disposed of, and the distinction is the
	// whole point: see resolveBindingKey.
	discard(windows.Handle)
	// adopt turns an opened or created handle into a binding key, taking
	// ownership of it.
	adopt(windows.Handle) (bindingKey, error)
}

// resolveBindingKey opens the container's key, or creates it, converging on
// whichever key is actually persisted under the name.
//
// # Recovering a stale key
//
// A per-boot KeyGuard key leaves its metadata on disk when the machine reboots.
// The name still opens and still reports Virtual Iso, but the isolated material
// is gone, so the handle cannot sign. That handle must be released and the key
// recreated - and it must NOT be deleted through.
//
// Deleting through it is the trap. NCryptDeleteKey resolves the *name*, not the
// object the stale handle was opened from, so if another process has already
// replaced the key, deleting through the old handle destroys the replacement and
// reports success. That was reproduced 3/3 against the Microsoft Software KSP on
// a development machine: open handle A, replace the name with B, delete through
// A, and B is gone. A process doing that during recovery silently removes a
// working key another process is already using.
//
// So recovery frees the handle and recreates with NCRYPT_OVERWRITE_KEY_FLAG,
// which is what MSAL .NET does - WindowsCngKeyOperations.TryGetOrCreateKeyGuard
// disposes the handle when its liveness probe fails and calls CreateFresh, whose
// creation options are OverwriteExistingKey together with the virtual-isolation
// and per-boot flags. Overwrite is required here rather than merely convenient:
// the name exists, so a create without it returns NTE_EXISTS for ever.
//
// Before overwriting, the name is reopened once. Another process may have
// replaced the dead key between this one's probe and its create, and adopting
// that replacement is strictly better than overwriting it. That narrows the
// window; it does not close it, and the residual case is described below.
//
// # Losing the race
//
// There are two ways to lose, and only one is reported. The reported one is
// create-time NTE_EXISTS - from either NCryptCreatePersistedKey or
// NCryptFinalizeKey - which means a rival already holds the name. The silent one
// is finalize-time: neither create writes the name, so two processes can both
// create, both finalize, and the later finalize replaces the earlier with
// nothing said. Every successful create is therefore followed by reopening the
// name and comparing public keys, and a creator that finds itself replaced
// discards its candidate and goes round to adopt the winner.
//
// Both are retryable within the bound rather than failures: a lost race means
// somebody else has a good key, which is the outcome this function wants.
//
// # What is not guaranteed
//
// withBindingKeyLock excludes other processes using this package. MSAL .NET
// takes no equivalent lock, so a Go process and a .NET process can still both be
// inside their create-finalize sequence, and the overwrite in the recovery path
// above can still land on a key .NET created moments earlier. Closing that needs
// a mutex convention both SDKs adopt; until then the reopen-and-compare check is
// what keeps this library from *using* a key that was replaced, which is the part
// it can guarantee alone.
func resolveBindingKey(c bindingKeyContainer, name string) (bindingKey, error) {
	for attempt := 0; attempt < bindingKeyCreateAttempts; attempt++ {
		overwrite := false
		key, existed, err := c.open()
		if err != nil {
			return bindingKey{}, err
		}
		if existed {
			if c.usable(key) {
				return c.adopt(key)
			}
			// Stale: release the handle, never delete through it.
			c.discard(key)

			// Somebody may have replaced it while this caller was probing.
			// Reopening once turns "overwrite a dead key" into "adopt a live
			// one" whenever the replacement has already landed.
			replacement, stillThere, err := c.open()
			if err != nil {
				return bindingKey{}, err
			}
			if stillThere {
				if c.usable(replacement) {
					return c.adopt(replacement)
				}
				c.discard(replacement)
				overwrite = true
			}
			// If the name has gone entirely, another process deleted it and an
			// ordinary create is both sufficient and safer.
		}

		key, err = c.create(overwrite)
		if err == nil {
			won, err := c.persisted(key)
			if err != nil {
				c.discard(key)
				return bindingKey{}, err
			}
			if won {
				return c.adopt(key)
			}
			// Replaced between this process's finalize and now. The candidate
			// is stranded - nothing will ever resolve to it again - so it is
			// released and the winner adopted on the next pass.
			c.discard(key)
			continue
		}
		if !errors.Is(err, errBindingKeyExists) {
			return bindingKey{}, err
		}
		// Somebody else created the key first. Go round again and adopt it
		// instead of replacing it.
	}
	return bindingKey{}, fmt.Errorf("%w: the binding key %q kept being replaced by another process while it was being provisioned",
		ErrCredentialGuardNotAvailable, name)
}

// cngBindingKeyContainer is the production implementation: the real NCrypt
// calls against one provider handle and one key name.
//
// It does not own the provider handle. getOrCreateKey opens it and releases it
// on every path that does not hand it to a returned binding key, which is what
// keeps the ownership rule in one place rather than spread across the loop.
type cngBindingKeyContainer struct {
	provider windows.Handle
	name     *uint16
}

func (c cngBindingKeyContainer) open() (windows.Handle, bool, error) {
	return openExistingKey(c.provider, c.name)
}

func (c cngBindingKeyContainer) usable(key windows.Handle) bool { return keyCanSign(key) }

func (c cngBindingKeyContainer) create(overwrite bool) (windows.Handle, error) {
	return createPersistedKey(c.provider, c.name, overwrite)
}

// persisted reopens the name and compares public keys, so a creator learns
// whether its finalize is still the one that counts.
//
// Only the public half is compared, which is all that is available: a KeyGuard
// private key never leaves the trustlet. That is enough, because two RSA keys
// with the same modulus and exponent are the same key for every purpose this
// flow has - the certificate is issued against the public key, and the handshake
// proves possession of the matching private half.
//
// A name that no longer resolves to anything is reported as not-ours rather than
// as an error: the rival created and then deleted, and the caller's next pass
// will create again.
func (c cngBindingKeyContainer) persisted(candidate windows.Handle) (bool, error) {
	current, existed, err := openExistingKey(c.provider, c.name)
	if err != nil {
		return false, err
	}
	if !existed {
		return false, nil
	}
	defer freeNCryptObject(current)

	ours, err := exportRSAPublic(candidate)
	if err != nil {
		return false, err
	}
	theirs, err := exportRSAPublic(current)
	if err != nil {
		return false, err
	}
	return ours.E == theirs.E && ours.N.Cmp(theirs.N) == 0, nil
}

func (c cngBindingKeyContainer) discard(key windows.Handle) { freeNCryptObject(key) }

func (c cngBindingKeyContainer) adopt(key windows.Handle) (bindingKey, error) {
	return finishBindingKey(key, c.provider)
}

// getOrCreateKey returns the binding key called name, creating it only when no
// usable key is present.
//
// Three layers of coordination sit under this call, and they do different jobs.
// bindingKeyGate keeps this process from racing itself, cheaply. The named mutex
// in withBindingKeyLock keeps other processes using this package from
// provisioning the same container at the same time. Neither is what makes the
// result correct: MSAL .NET takes no equivalent lock, and the mutex is
// deliberately allowed to fail open, so the persisted-winner check inside
// resolveBindingKey is the guarantee. See resolveBindingKey for the race the
// check exists for.
func (keyGuardProvider) getOrCreateKey(name string) (bindingKey, error) {
	gate := bindingKeyGate(name)
	gate.Lock()
	defer gate.Unlock()

	var key bindingKey
	var err error
	withBindingKeyLock(name, func() {
		key, err = provisionBindingKey(name)
	})
	return key, err
}

// provisionBindingKey does the work of getOrCreateKey while both locks are held.
func provisionBindingKey(name string) (bindingKey, error) {
	keyName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return bindingKey{}, fmt.Errorf("managedidentity: encoding the key name: %w", err)
	}
	provider, err := openProvider()
	if err != nil {
		return bindingKey{}, err
	}
	// The provider handle is released on every path except the one that hands
	// it to a binding key, whose Close then owns it.
	adopted := false
	defer func() {
		if !adopted {
			freeNCryptObject(provider)
		}
	}()

	key, err := resolveBindingKey(cngBindingKeyContainer{provider: provider, name: keyName}, name)
	if err != nil {
		return bindingKey{}, err
	}
	adopted = true
	return key, nil
}

// openKey returns the binding key called name without creating one.
//
// A key that is absent, and a key that is present but can no longer sign, are
// both reported as errBindingKeyNotFound: the caller is asking whether the key a
// certificate was issued against is still usable, and neither case is.
// Deliberately nothing is created, deleted or replaced here, so a cache read
// leaves the machine exactly as it found it.
func (keyGuardProvider) openKey(name string) (bindingKey, error) {
	keyName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return bindingKey{}, fmt.Errorf("managedidentity: encoding the key name: %w", err)
	}
	provider, err := openProvider()
	if err != nil {
		return bindingKey{}, err
	}
	adopted := false
	defer func() {
		if !adopted {
			freeNCryptObject(provider)
		}
	}()

	key, existed, err := openExistingKey(provider, keyName)
	if err != nil {
		return bindingKey{}, err
	}
	if !existed {
		return bindingKey{}, errBindingKeyNotFound
	}
	if !keyCanSign(key) {
		freeNCryptObject(key)
		return bindingKey{}, errBindingKeyNotFound
	}
	bound, err := finishBindingKey(key, provider)
	if err != nil {
		return bindingKey{}, err
	}
	adopted = true
	return bound, nil
}

// finishBindingKey reads the public half and the isolation property off an open
// key and wraps it as a signer.
//
// Ownership is asymmetric on purpose. On success it takes both handles, which
// the returned key's Close releases. On failure it releases only the key handle
// and leaves the provider alone, because the provider belongs to the caller
// until an adoption succeeds: getOrCreateKey and openKey each release it exactly
// once, from a deferred cleanup that runs on every path they do not hand it
// away. Freeing it here as well would be a double free.
func finishBindingKey(key, provider windows.Handle) (bindingKey, error) {
	public, err := exportRSAPublic(key)
	if err != nil {
		freeNCryptObject(key)
		return bindingKey{}, err
	}

	isolated, known, err := getDWORDProperty(key, ncryptVirtualIsoProperty)
	if err != nil {
		freeNCryptObject(key)
		return bindingKey{}, err
	}
	kind := keyTypeSoftware
	if known && isolated == 1 {
		kind = keyTypeKeyGuard
	}

	signer := &ncryptSigner{key: key, provider: provider, public: public}
	return bindingKey{Signer: signer, Type: kind, Close: signer.Close}, nil
}

// deleteKeyHandle deletes the persisted key an open handle refers to. CNG frees
// the handle on success, so the caller must not free it again.
//
// NCryptDeleteKey resolves the *name*, not the object the handle was opened
// from, so a handle that has gone stale deletes whatever now holds the name -
// including a replacement another process just created, and it reports success
// while doing it. That is why the stale-key recovery path in resolveBindingKey
// never routes through here: it frees the handle and recreates with overwrite
// instead. The only caller is deleteKey, which opens the name and deletes it in
// the same breath because deleting is what it was asked to do.
func deleteKeyHandle(key windows.Handle) error {
	status, _, _ := syscall.SyscallN(procNCryptDeleteKey.Addr(), uintptr(key), uintptr(ncryptSilentFlag))
	if status != 0 {
		freeNCryptObject(key)
		return ncryptStatusError("NCryptDeleteKey", status)
	}
	return nil
}

// deleteKey removes a persisted key so the next request mints a fresh one.
func (keyGuardProvider) deleteKey(name string) error {
	keyName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("managedidentity: encoding the key name: %w", err)
	}
	provider, err := openProvider()
	if err != nil {
		return err
	}
	defer freeNCryptObject(provider)

	key, existed, err := openExistingKey(provider, keyName)
	if err != nil {
		return err
	}
	if !existed {
		return nil
	}
	return deleteKeyHandle(key)
}

// exportRSAPublic reads the public half of a CNG key.
func exportRSAPublic(key windows.Handle) (*rsa.PublicKey, error) {
	blobType, err := windows.UTF16PtrFromString(rsaPublicBlob)
	if err != nil {
		return nil, fmt.Errorf("managedidentity: encoding the blob type: %w", err)
	}
	var size uint32
	status, _, _ := syscall.SyscallN(procNCryptExportKey.Addr(),
		uintptr(key), 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0,
		uintptr(unsafe.Pointer(&size)), uintptr(ncryptSilentFlag),
	)
	if status != 0 {
		return nil, ncryptStatusError("NCryptExportKey(size)", status)
	}
	if size < rsaBlobHeaderLen {
		return nil, fmt.Errorf("managedidentity: CNG reported a %d byte public key blob, too short to be valid", size)
	}
	blob := make([]byte, size)
	status, _, _ = syscall.SyscallN(procNCryptExportKey.Addr(),
		uintptr(key), 0, uintptr(unsafe.Pointer(blobType)), 0,
		uintptr(unsafe.Pointer(&blob[0])), uintptr(len(blob)),
		uintptr(unsafe.Pointer(&size)), uintptr(ncryptSilentFlag),
	)
	if status != 0 {
		return nil, ncryptStatusError("NCryptExportKey", status)
	}
	return parseRSAPublicKeyBlob(blob[:size])
}

// parseRSAPublicKeyBlob decodes a BCRYPT_RSAKEY_BLOB carrying a public key. The
// header is six little-endian ULONGs followed by the exponent and modulus, both
// big-endian.
func parseRSAPublicKeyBlob(blob []byte) (*rsa.PublicKey, error) {
	if len(blob) < rsaBlobHeaderLen {
		return nil, fmt.Errorf("managedidentity: the public key blob is %d bytes, too short for a BCRYPT_RSAKEY_BLOB", len(blob))
	}
	magic := binary.LittleEndian.Uint32(blob[0:4])
	if magic != bcryptRSAPublicMagicValue {
		return nil, fmt.Errorf("managedidentity: public key blob magic 0x%08X is not BCRYPT_RSAPUBLIC_MAGIC", magic)
	}
	expLen := binary.LittleEndian.Uint32(blob[8:12])
	modLen := binary.LittleEndian.Uint32(blob[12:16])
	// Guard the additions against overflow before indexing.
	if uint64(rsaBlobHeaderLen)+uint64(expLen)+uint64(modLen) > uint64(len(blob)) {
		return nil, fmt.Errorf("managedidentity: the public key blob is truncated")
	}
	if expLen == 0 || modLen == 0 {
		return nil, fmt.Errorf("managedidentity: the public key blob has an empty exponent or modulus")
	}
	exponent := new(big.Int).SetBytes(blob[rsaBlobHeaderLen : rsaBlobHeaderLen+expLen])
	modulus := new(big.Int).SetBytes(blob[rsaBlobHeaderLen+expLen : rsaBlobHeaderLen+expLen+modLen])
	if !exponent.IsInt64() || exponent.Int64() <= 0 || exponent.Int64() > 1<<31-1 {
		return nil, fmt.Errorf("managedidentity: the public key exponent is out of range")
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
}

// ncryptSigner is a crypto.Signer over a CNG key handle. For a KeyGuard key the
// private material stays inside the VBS trustlet: signing crosses the boundary,
// the key never does.
type ncryptSigner struct {
	mu       sync.Mutex
	key      windows.Handle
	provider windows.Handle
	public   *rsa.PublicKey
	closed   bool
}

func (s *ncryptSigner) Public() crypto.PublicKey { return s.public }

// Close releases the CNG handles. It is safe to call more than once.
func (s *ncryptSigner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	freeNCryptObject(s.key)
	freeNCryptObject(s.provider)
	s.key, s.provider = 0, 0
	return nil
}

// pssSaltLength resolves the salt length a PSS signature should use, in bytes.
//
// crypto.Signer's contract gives the two sentinels different meanings, and
// treating them as the same value - which this did - makes rsa.PSSSaltLengthAuto
// produce a signature a strict verifier can reject, because a caller asking for
// Auto is asking for the largest salt the modulus allows, not for the hash size.
//
//   - PSSSaltLengthEqualsHash is exactly the hash length.
//   - PSSSaltLengthAuto is the maximum the encoding permits. RFC 8017 section
//     9.1.1 puts an EMSA-PSS encoding in emLen = ceil((modBits-1)/8) bytes and
//     spends hLen on the hash and one byte on the trailer, plus the 0x01
//     separator, leaving emLen - hLen - 2 for the salt. This is what
//     crypto/rsa's own signPSSWithSalt computes for the same sentinel.
//   - Any other value is an explicit request and is used as given.
//
// A modulus too small to carry the hash at all yields a negative maximum, which
// is refused rather than wrapped into an enormous unsigned salt.
func pssSaltLength(requested int, hash crypto.Hash, public *rsa.PublicKey) (int, error) {
	hashLen := hash.Size()
	switch requested {
	case rsa.PSSSaltLengthEqualsHash:
		return hashLen, nil
	case rsa.PSSSaltLengthAuto:
		if public == nil || public.N == nil {
			return 0, fmt.Errorf("managedidentity: the maximum PSS salt length cannot be derived without the public key")
		}
		// emBits is one less than the modulus bit length; emLen rounds it up to
		// whole bytes.
		emLen := (public.N.BitLen() - 1 + 7) / 8
		maxSalt := emLen - hashLen - 2
		if maxSalt < 0 {
			return 0, fmt.Errorf("managedidentity: a %d bit key is too small to carry a %v PSS signature", public.N.BitLen(), hash)
		}
		return maxSalt, nil
	default:
		if requested < 0 {
			return 0, fmt.Errorf("managedidentity: invalid PSS salt length %d", requested)
		}
		return requested, nil
	}
}

// algorithmIdentifier maps a hash to the BCRYPT algorithm string CNG expects.
func algorithmIdentifier(h crypto.Hash) (*uint16, error) {
	var name string
	switch h {
	case crypto.SHA256:
		name = "SHA256"
	case crypto.SHA384:
		name = "SHA384"
	case crypto.SHA512:
		name = "SHA512"
	default:
		return nil, fmt.Errorf("managedidentity: unsupported hash %v", h)
	}
	return windows.UTF16PtrFromString(name)
}

// Sign signs digest through CNG. The IMDSv2 CSR is signed with RSA-PSS, and the
// TLS stack uses both PSS and PKCS#1 v1.5 depending on the negotiated protocol
// version, so both paddings are supported.
func (s *ncryptSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, fmt.Errorf("managedidentity: signer options are required")
	}
	hash := opts.HashFunc()
	if hash.Size() != len(digest) {
		return nil, fmt.Errorf("managedidentity: digest is %d bytes but %v produces %d", len(digest), hash, hash.Size())
	}
	algID, err := algorithmIdentifier(hash)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("%s: the key is closed", bindingKeySignFailureMarker)
	}

	var padInfo unsafe.Pointer
	var flags uintptr
	pssInfo := bcryptPSSPaddingInfo{}
	pkcs1Info := bcryptPKCS1PaddingInfo{}
	if pss, ok := opts.(*rsa.PSSOptions); ok {
		saltLength, err := pssSaltLength(pss.SaltLength, hash, s.public)
		if err != nil {
			return nil, err
		}
		// #nosec G115 -- pssSaltLength bounds the value to [0, emLen), which is
		// derived from the modulus size and cannot reach uint32's range.
		pssInfo = bcryptPSSPaddingInfo{pszAlgID: algID, cbSalt: uint32(saltLength)}
		padInfo = unsafe.Pointer(&pssInfo)
		flags = bcryptPadPSSFlag
	} else {
		pkcs1Info = bcryptPKCS1PaddingInfo{pszAlgID: algID}
		padInfo = unsafe.Pointer(&pkcs1Info)
		flags = bcryptPadPKCS1Flag
	}
	// The padding struct holds a pointer to algID, and CNG dereferences both for
	// the duration of each call below.
	defer runtime.KeepAlive(algID)
	defer runtime.KeepAlive(&pssInfo)
	defer runtime.KeepAlive(&pkcs1Info)

	var needed uint32
	status, _, _ := syscall.SyscallN(procNCryptSignHash.Addr(),
		uintptr(s.key), uintptr(padInfo),
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		0, 0, uintptr(unsafe.Pointer(&needed)), flags|ncryptSilentFlag,
	)
	if status != 0 {
		return nil, fmt.Errorf("%s: %w", bindingKeySignFailureMarker, ncryptStatusError("NCryptSignHash(size)", status))
	}
	// A successful size query that asks for nothing is not something CNG should
	// ever do, but believing it would index an empty slice below and panic
	// inside a signing path that crypto/tls calls on every handshake.
	if needed == 0 {
		return nil, fmt.Errorf("%s: NCryptSignHash reported a zero-length signature", bindingKeySignFailureMarker)
	}
	signature := make([]byte, needed)
	status, _, _ = syscall.SyscallN(procNCryptSignHash.Addr(),
		uintptr(s.key), uintptr(padInfo),
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&signature[0])), uintptr(len(signature)),
		uintptr(unsafe.Pointer(&needed)), flags|ncryptSilentFlag,
	)
	if status != 0 {
		return nil, fmt.Errorf("%s: %w", bindingKeySignFailureMarker, ncryptStatusError("NCryptSignHash", status))
	}
	return signature[:needed], nil
}

// newKeyProvider returns the KeyGuard-backed provider on Windows.
func newKeyProvider() keyProvider { return keyGuardProvider{} }
