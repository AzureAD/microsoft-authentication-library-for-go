// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build windows

package managedidentity

import (
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"sync"
	"syscall"
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
	ncryptOverwriteKeyFlag  = 0x00000080

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

// createPersistedKey mints a new VBS-isolated RSA key called name.
func createPersistedKey(provider windows.Handle, name *uint16) (windows.Handle, error) {
	algorithm, err := windows.UTF16PtrFromString(ncryptRSAAlgorithm)
	if err != nil {
		return 0, fmt.Errorf("managedidentity: encoding the algorithm name: %w", err)
	}
	var key windows.Handle
	status, _, _ := syscall.SyscallN(procNCryptCreatePersistedKey.Addr(),
		uintptr(provider),
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(algorithm)),
		uintptr(unsafe.Pointer(name)),
		0,
		uintptr(ncryptUseVirtualIsolationFlag|ncryptUsePerBootKeyFlag|ncryptOverwriteKeyFlag),
	)
	if status != 0 {
		if statusCode(status) == nteExists {
			return 0, fmt.Errorf("%w: the key already exists and could not be replaced", ErrCredentialGuardNotAvailable)
		}
		// A host without VBS rejects the virtual isolation flag outright.
		return 0, fmt.Errorf("%w: %v", ErrCredentialGuardNotAvailable, ncryptStatusError("NCryptCreatePersistedKey", status))
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
	status, _, _ = syscall.SyscallN(procNCryptFinalizeKey.Addr(), uintptr(key), uintptr(ncryptSilentFlag))
	if status != 0 {
		freeNCryptObject(key)
		return 0, fmt.Errorf("%w: %v", ErrCredentialGuardNotAvailable, ncryptStatusError("NCryptFinalizeKey", status))
	}
	return key, nil
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

// bindingKeyGates serializes provisioning of a CNG container.
//
// The container is process-wide - one name, shared by every identity - while
// bindingCertCache's gate is keyed by identity and attestation mode. Two
// identities therefore take different certificate gates and would provision the
// same container concurrently. createPersistedKey passes
// NCRYPT_OVERWRITE_KEY_FLAG, and because the key is per-boot keyCanSign fails
// for every identity after a reboot, so concurrent first calls are guaranteed to
// both take the create-and-overwrite branch. The loser's freshly issued
// certificate would then be bound to a key that no longer exists, costing a
// second /issuecredential call against a rate-limited service, and the overwrite
// can invalidate a handle another goroutine already holds. This is the
// key-provisioning counterpart of the gate attestation.go takes for the same
// process-wide reason.
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

// getOrCreateKey returns the binding key called name, creating it when absent.
func (keyGuardProvider) getOrCreateKey(name string) (bindingKey, error) {
	gate := bindingKeyGate(name)
	gate.Lock()
	defer gate.Unlock()

	keyName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return bindingKey{}, fmt.Errorf("managedidentity: encoding the key name: %w", err)
	}
	provider, err := openProvider()
	if err != nil {
		return bindingKey{}, err
	}

	key, existed, err := openExistingKey(provider, keyName)
	if err != nil {
		freeNCryptObject(provider)
		return bindingKey{}, err
	}
	if existed && !keyCanSign(key) {
		// The key survived a reboot in name only. Replacing it changes the
		// public key, so any certificate already issued against the old one is
		// worthless; the caller discards its cache when the key is replaced.
		freeNCryptObject(key)
		existed = false
	}
	if !existed {
		if key, err = createPersistedKey(provider, keyName); err != nil {
			freeNCryptObject(provider)
			return bindingKey{}, err
		}
	}

	public, err := exportRSAPublic(key)
	if err != nil {
		freeNCryptObject(key)
		freeNCryptObject(provider)
		return bindingKey{}, err
	}

	isolated, known, err := getDWORDProperty(key, ncryptVirtualIsoProperty)
	if err != nil {
		freeNCryptObject(key)
		freeNCryptObject(provider)
		return bindingKey{}, err
	}
	kind := keyTypeSoftware
	if known && isolated == 1 {
		kind = keyTypeKeyGuard
	}

	signer := &ncryptSigner{key: key, provider: provider, public: public}
	return bindingKey{Signer: signer, Type: kind, Close: signer.Close}, nil
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
	status, _, _ := syscall.SyscallN(procNCryptDeleteKey.Addr(), uintptr(key), uintptr(ncryptSilentFlag))
	if status != 0 {
		freeNCryptObject(key)
		return ncryptStatusError("NCryptDeleteKey", status)
	}
	// NCryptDeleteKey frees the handle on success.
	return nil
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
		saltLength := pss.SaltLength
		switch saltLength {
		case rsa.PSSSaltLengthAuto, rsa.PSSSaltLengthEqualsHash:
			saltLength = hash.Size()
		}
		if saltLength < 0 {
			return nil, fmt.Errorf("managedidentity: invalid PSS salt length %d", pss.SaltLength)
		}
		// #nosec G115 -- the guard above makes saltLength non-negative, and a PSS
		// salt is bounded by the modulus size, so it cannot overflow uint32.
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
