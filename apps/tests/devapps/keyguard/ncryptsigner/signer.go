//go:build windows

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package ncryptsigner exposes a certificate from a Windows certificate store whose private key is
// held by CNG -- including a KeyGuard (VBS-isolated) key -- as a [crypto.Signer], so it can be used
// directly as [tls.Certificate].PrivateKey and therefore as an MSAL credential via
// confidential.NewCredFromTLSCertificate.
//
// A KeyGuard key can never be an *rsa.PrivateKey: the private material lives inside a
// virtualization-based-security trustlet and is not retrievable, so anything that type-asserts to
// *rsa.PrivateKey is a hard block. crypto/tls, by contrast, only ever needs a crypto.Signer, which
// is exactly what CNG can provide. Every signature here is produced by NCryptSignHash; no key
// material crosses the CNG boundary.
//
// This package is sample and test code. It is deliberately NOT part of the MSAL public API: MSAL Go
// stays platform-agnostic and takes any crypto.Signer, so the Windows-specific plumbing belongs to
// the application. Copy it into your own project and adapt it; do not import it as a supported API,
// because it carries no compatibility guarantee.
package ncryptsigner

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ncrypt.dll holds the CNG key-storage-provider entry points. crypt32.dll's certificate APIs are
// already wrapped with typed signatures by golang.org/x/sys/windows, so only the NCrypt* functions
// need lazy binding here. NewLazySystemDLL resolves out of %SystemRoot%\System32 only, which avoids
// DLL preloading attacks.
//
// Every one of these that is handed a pointer is invoked through syscall.SyscallN rather than
// LazyProc.Call. Converting unsafe.Pointer to uintptr is only defined when the conversion appears in
// the argument list of an assembly-implemented call: the compiler and runtime recognize that shape
// and keep the referent valid for the call. LazyProc.Call is ordinary Go, so the operands would be
// spilled into a variadic []uintptr and carried across further Go calls, each of which can grow --
// and therefore move -- the stack while only a bare integer refers to the object. runtime.KeepAlive
// does not close that gap: it guarantees liveness, not a fixed address. runtime.Pinner would, but it
// requires Go 1.21 and this module declares 1.18. SyscallN puts the conversions directly in the
// assembly call's own argument list, which is the shape the rule is written for.
var (
	ncrypt = windows.NewLazySystemDLL("ncrypt.dll")

	procNCryptSignHash    = ncrypt.NewProc("NCryptSignHash")
	procNCryptFreeObject  = ncrypt.NewProc("NCryptFreeObject")
	procNCryptGetProperty = ncrypt.NewProc("NCryptGetProperty")
	procNCryptExportKey   = ncrypt.NewProc("NCryptExportKey")
)

const (
	// BCRYPT_PAD_* select the RSA padding NCryptSignHash applies.
	bcryptPadPKCS1 = 0x00000002
	bcryptPadPSS   = 0x00000008

	// certFindSHA256Hash is CERT_FIND_SHA256_HASH, i.e. CERT_COMPARE_SHA256_HASH (22) <<
	// CERT_COMPARE_SHIFT (16). It is declared here rather than taken from golang.org/x/sys/windows
	// because the version this module pins exposes only the SHA-1 and MD5 find types --
	// windows.CERT_FIND_HASH is itself an alias for CERT_FIND_SHA1_HASH. wincrypt.h defines this
	// value directly beside CERT_FIND_SHA1_HASH with no version guard, so CryptoAPI accepts it
	// wherever the SHA-1 form works.
	certFindSHA256Hash = 22 << 16 // 0x00160000

	// Thumbprint lengths in bytes. Certificates are looked up by SHA-256, because SHA-1 is
	// collision-broken and a lookup key that can collide is a certificate-substitution risk. The
	// SHA-1 length is recognized only to return a better error: it is the value every Windows
	// surface displays.
	sha1ThumbprintLen   = 20
	sha256ThumbprintLen = 32

	// NCRYPT_VIRTUAL_ISO_PROPERTY. CNG sets it to 1 for keys whose material is held by the VBS
	// trustlet, which is what "KeyGuard" means in practice.
	virtualIsoProperty = "Virtual Iso"

	// chainURLRetrievalTimeoutMs bounds any AIA fetch CertGetCertificateChain performs to complete a
	// chain whose intermediates aren't installed locally. Without a bound, chain building on a host
	// with no outbound network can stall for the CryptoAPI default.
	chainURLRetrievalTimeoutMs = 10000

	// SECURITY_STATUS codes. NCrypt reports "no such property" with one of the latter three, which
	// this package treats as a definitive answer rather than a failure.
	errorSuccessSecurity = 0
	nteNotFound          = 0x80090011
	nteInvalidParameter  = 0x80090027
	nteNotSupported      = 0x80090029

	// rsaPublicBlobType is BCRYPT_RSAPUBLIC_BLOB. It is the one blob type a VBS-isolated key will
	// export: CNG refuses every blob carrying private material for such a key, but places no
	// restriction on the public half.
	rsaPublicBlobType = "RSAPUBLICBLOB"

	// bcryptRSAPublicMagic is BCRYPT_RSAPUBLIC_MAGIC, the first ULONG of a BCRYPT_RSAKEY_BLOB that
	// carries only a public key. It reads "RSA1" in little-endian bytes.
	bcryptRSAPublicMagic = 0x31415352

	// rsaKeyBlobHeaderLen is sizeof(BCRYPT_RSAKEY_BLOB): six ULONGs, namely Magic, BitLength,
	// cbPublicExp, cbModulus, cbPrime1 and cbPrime2.
	rsaKeyBlobHeaderLen = 24
)

// cryptHashBlob is CRYPT_HASH_BLOB, the findPara CertFindCertificateInStore expects for a hash
// find type such as CERT_FIND_SHA256_HASH. It is length-prefixed by cbData, so it carries a hash of
// any width.
type cryptHashBlob struct {
	cbData uint32
	pbData *byte
}

// pkcs1PaddingInfo is BCRYPT_PKCS1_PADDING_INFO.
type pkcs1PaddingInfo struct {
	pszAlgID *uint16
}

// pssPaddingInfo is BCRYPT_PSS_PADDING_INFO.
type pssPaddingInfo struct {
	pszAlgID *uint16
	cbSalt   uint32
}

// Signer is a crypto.Signer backed by a CNG key handle. The private key never leaves the CNG/VBS
// boundary.
//
// A Signer holds OS handles and must be closed with [Signer.Close] when it is no longer needed.
// It is safe for concurrent use: crypto/tls may sign from any goroutine.
type Signer struct {
	cert     *x509.Certificate
	chain    [][]byte
	chainErr error
	// pub is the certificate's public key. Open verifies it against the CNG key handle's own
	// public key, so it is also the key hKey signs with.
	pub *rsa.PublicKey

	// mu guards hKey against use-after-free if Close races a TLS handshake.
	mu      sync.RWMutex
	hKey    windows.Handle
	closed  bool
	release func()
}

// Certificate returns the leaf certificate.
func (s *Signer) Certificate() *x509.Certificate { return s.cert }

// Chain returns the DER-encoded certificate chain, leaf first, in the order [tls.Certificate] and
// the JWT x5c header both require.
//
// The chain is built with CertGetCertificateChain and includes any intermediates, but deliberately
// omits a self-signed root: x5c conventionally carries leaf plus intermediates, and Entra does not
// need the root to validate the certificate. When the chain could not be built the slice degrades to
// the leaf alone and [Signer.ChainError] explains why.
func (s *Signer) Chain() [][]byte { return s.chain }

// ChainError returns the reason [Signer.Chain] holds only the leaf, or nil if a full chain was
// built. It is a warning, not a failure: [Open] still succeeds with a leaf-only chain, because a
// leaf-only x5c is enough for Entra when the intermediates are already known to it.
func (s *Signer) ChainError() error { return s.chainErr }

// Public implements crypto.Signer.
//
// It returns the public key parsed from the certificate, which is cheap and allocation-free. That is
// only sound because [Open] proves the CNG key handle's public key is this same key before returning
// a Signer, so the certificate is not merely asserting the association -- see the check there. A
// signer that reported its certificate's key without that proof would make
// confidential.NewCredFromTLSCertificate's leaf/key identity check compare the certificate against
// itself, so it could never fail.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Close releases the CNG key handle, the certificate context and the store handle. It is idempotent.
//
// Close returns nothing because none of the underlying releases can fail in a way a caller could act
// on, which also keeps "defer signer.Close()" correct at every call site.
func (s *Signer) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.release != nil {
		s.release()
		s.release = nil
	}
}

func algIDForHash(h crypto.Hash) (*uint16, error) {
	switch h {
	case crypto.SHA256:
		return windows.StringToUTF16Ptr("SHA256"), nil
	case crypto.SHA384:
		return windows.StringToUTF16Ptr("SHA384"), nil
	case crypto.SHA512:
		return windows.StringToUTF16Ptr("SHA512"), nil
	default:
		return nil, fmt.Errorf("ncryptsigner: unsupported hash %v", h)
	}
}

// Sign implements crypto.Signer. crypto/tls calls it with *rsa.PSSOptions for TLS 1.3
// (rsa_pss_rsae_*) and with a bare crypto.Hash for TLS 1.2 PKCS#1 v1.5, so both paddings are
// supported. The rand argument is ignored: CNG supplies its own randomness inside the key's
// protection boundary.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	algID, err := algIDForHash(hash)
	if err != nil {
		return nil, err
	}
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("ncryptsigner: digest length %d does not match %v", len(digest), hash)
	}

	if pss, ok := opts.(*rsa.PSSOptions); ok {
		saltLen := pss.SaltLength
		switch saltLen {
		case rsa.PSSSaltLengthAuto, rsa.PSSSaltLengthEqualsHash:
			// Auto means "as large as possible" when signing, but CNG wants an explicit length and
			// every TLS PSS scheme uses a salt the size of the hash.
			saltLen = hash.Size()
		}
		// Any other negative value is not a defined salt length. Without this the conversion below
		// wraps: a SaltLength of -7 would reach CNG as cbSalt 4294967289. crypto/rsa rejects the
		// same inputs, so this only refuses what the standard library already refuses.
		if saltLen < 0 {
			return nil, fmt.Errorf("ncryptsigner: invalid PSS salt length %d", saltLen)
		}
		// #nosec G115 -- the guard above makes saltLen non-negative, and a PSS salt is bounded by the
		// modulus size, so it cannot overflow uint32. gosec cannot follow the value through the switch.
		info := pssPaddingInfo{pszAlgID: algID, cbSalt: uint32(saltLen)}
		sig, err := s.signHash(unsafe.Pointer(&info), digest, bcryptPadPSS)
		runtime.KeepAlive(&info)
		return sig, err
	}

	info := pkcs1PaddingInfo{pszAlgID: algID}
	sig, err := s.signHash(unsafe.Pointer(&info), digest, bcryptPadPKCS1)
	runtime.KeepAlive(&info)
	return sig, err
}

// signHash performs the two-call NCryptSignHash sequence: ask CNG for the signature size, then sign.
func (s *Signer) signHash(padInfo unsafe.Pointer, digest []byte, flags uintptr) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, fmt.Errorf("ncryptsigner: signer is closed")
	}

	var size uint32
	status, _, _ := syscall.SyscallN(procNCryptSignHash.Addr(),
		uintptr(s.hKey), uintptr(padInfo),
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		0, 0, uintptr(unsafe.Pointer(&size)), flags,
	)
	if status != errorSuccessSecurity {
		return nil, ncryptError("NCryptSignHash(size)", status)
	}

	sig := make([]byte, size)
	status, _, _ = syscall.SyscallN(procNCryptSignHash.Addr(),
		uintptr(s.hKey), uintptr(padInfo),
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(size),
		uintptr(unsafe.Pointer(&size)), flags,
	)
	runtime.KeepAlive(digest)
	if status != errorSuccessSecurity {
		return nil, ncryptError("NCryptSignHash", status)
	}
	if int(size) > len(sig) {
		return nil, fmt.Errorf("ncryptsigner: NCryptSignHash reported %d signature bytes into a %d-byte buffer",
			size, len(sig))
	}
	return sig[:size], nil
}

// IsVirtualIsolated reports the CNG "Virtual Iso" property, which is 1 for a KeyGuard
// (VBS-isolated) key and absent or 0 otherwise.
//
// Applications should check this themselves whenever isolation is a security requirement. MSAL
// decides how to sign purely from the Go type of the key, so it cannot tell a VBS-isolated
// key from a software key wrapped in a crypto.Signer, and it makes no isolation claim either way. A
// provisioning step that silently fell back to a software key is otherwise invisible from Go.
//
// A provider that does not implement the property reports (false, nil): the property's absence is a
// definitive "not isolated", not an error.
func (s *Signer) IsVirtualIsolated() (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return false, fmt.Errorf("ncryptsigner: signer is closed")
	}

	prop := windows.StringToUTF16Ptr(virtualIsoProperty)
	var val uint32
	var got uint32
	status, _, _ := syscall.SyscallN(procNCryptGetProperty.Addr(),
		uintptr(s.hKey), uintptr(unsafe.Pointer(prop)),
		uintptr(unsafe.Pointer(&val)), unsafe.Sizeof(val),
		uintptr(unsafe.Pointer(&got)), 0,
	)
	runtime.KeepAlive(prop)
	switch status {
	case errorSuccessSecurity:
		return val == 1, nil
	case nteNotSupported, nteNotFound, nteInvalidParameter:
		return false, nil
	default:
		return false, ncryptError("NCryptGetProperty("+virtualIsoProperty+")", status)
	}
}

// ncryptError renders a SECURITY_STATUS both as the Windows message (NTE_* codes are in the system
// message table) and as the raw code, because the raw code is what CNG documentation refers to.
func ncryptError(op string, status uintptr) error {
	// #nosec G115 -- SECURITY_STATUS is a 32-bit value widened into a uintptr by the syscall ABI;
	// narrowing it back is what produces the 0x-prefixed code CNG documentation uses.
	return fmt.Errorf("ncryptsigner: %s failed: %w (0x%08X)", op, windows.Errno(status), uint32(status))
}

// Open finds a certificate by SHA-256 thumbprint in the given store and returns a Signer bound to
// its CNG key. storeLocation is "CurrentUser" or "LocalMachine"; storeName is a store such as "My".
//
// The caller must call [Signer.Close] to release the OS handles.
func Open(storeLocation, storeName, thumbprint string) (*Signer, error) {
	loc, err := storeLocationFlag(storeLocation)
	if err != nil {
		return nil, err
	}
	if storeName == "" {
		return nil, fmt.Errorf("ncryptsigner: store name can't be empty")
	}
	hash, err := parseThumbprint(thumbprint)
	if err != nil {
		return nil, err
	}

	name, err := windows.UTF16PtrFromString(storeName)
	if err != nil {
		return nil, fmt.Errorf("ncryptsigner: bad store name %q: %w", storeName, err)
	}
	// The store is opened read-only, and OPEN_EXISTING keeps CryptoAPI from silently creating an
	// empty store when the name is wrong -- that would otherwise surface as a confusing
	// "certificate not found".
	hStore, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM_W, 0, 0,
		loc|windows.CERT_STORE_READONLY_FLAG|windows.CERT_STORE_OPEN_EXISTING_FLAG,
		uintptr(unsafe.Pointer(name)),
	)
	runtime.KeepAlive(name)
	if err != nil {
		return nil, fmt.Errorf("ncryptsigner: CertOpenStore(%s\\%s) failed: %w", storeLocation, storeName, err)
	}
	// Every failure past this point has to release what has already been acquired. cleanup is set to
	// nil once ownership transfers to the returned Signer.
	cleanup := func() { _ = windows.CertCloseStore(hStore, 0) }
	defer func() {
		if cleanup != nil {
			cleanup()
		}
	}()

	// #nosec G115 -- parseThumbprint returns exactly sha256ThumbprintLen bytes or an error, so the
	// length is a small constant and the index below is in range.
	blob := cryptHashBlob{cbData: uint32(len(hash)), pbData: &hash[0]}
	ctx, err := windows.CertFindCertificateInStore(
		hStore, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0,
		certFindSHA256Hash, unsafe.Pointer(&blob), nil,
	)
	runtime.KeepAlive(&blob)
	if err != nil {
		return nil, fmt.Errorf("ncryptsigner: certificate %s not found in %s\\%s: %w",
			thumbprint, storeLocation, storeName, err)
	}
	closeStore := cleanup
	cleanup = func() {
		_ = windows.CertFreeCertificateContext(ctx)
		closeStore()
	}

	der := derFromContext(ctx)
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ncryptsigner: parse certificate: %w", err)
	}
	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ncryptsigner: only RSA certificates are supported, got %T", leaf.PublicKey)
	}

	// CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG forces an NCRYPT_KEY_HANDLE, which is required for
	// VBS-isolated keys: they have no legacy CAPI representation. CRYPT_ACQUIRE_SILENT_FLAG keeps
	// the provider from putting up UI on a headless machine.
	var hKey windows.Handle
	var keySpec uint32
	var callerFree bool
	err = windows.CryptAcquireCertificatePrivateKey(
		ctx, windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG|windows.CRYPT_ACQUIRE_SILENT_FLAG, nil,
		&hKey, &keySpec, &callerFree,
	)
	if err != nil {
		return nil, fmt.Errorf("ncryptsigner: CryptAcquireCertificatePrivateKey failed "+
			"(the certificate has no CNG private key, or this process can't reach it): %w", err)
	}
	// Fold the key handle into cleanup now rather than at the end, so every failure between here
	// and the return releases it. NCryptFreeObject takes no pointer, so LazyProc.Call is fine.
	if callerFree {
		releaseRest := cleanup
		cleanup = func() {
			_, _, _ = procNCryptFreeObject.Call(uintptr(hKey))
			releaseRest()
		}
	}

	// Prove the key actually belongs to the certificate. CryptAcquireCertificatePrivateKey follows
	// CERT_KEY_PROV_INFO_PROP_ID, a mutable Windows store property, so the certificate-to-key
	// association is metadata that nothing has cryptographically verified. Exporting the public half
	// and comparing it is what turns that claim into proof; CNG allows it even for a VBS-isolated
	// key, because only the private half is protected.
	//
	// Without this, Signer.Public would report a key the handle might not hold, and every consumer
	// that checks a certificate against its signer -- including
	// confidential.NewCredFromTLSCertificate -- would be comparing the certificate's key against
	// itself and could never detect the mismatch. It would instead surface as an unexplained TLS
	// handshake failure against Entra.
	cngPub, err := exportRSAPublicKey(hKey)
	if err != nil {
		return nil, err
	}
	if !pub.Equal(cngPub) {
		return nil, fmt.Errorf("ncryptsigner: the CNG key reached through certificate %s holds a "+
			"different public key than the certificate does, so the store's key association is wrong",
			thumbprint)
	}

	chain, chainErr := buildChain(ctx, hStore, der)

	s := &Signer{cert: leaf, chain: chain, chainErr: chainErr, pub: pub, hKey: hKey}
	s.release = cleanup
	cleanup = nil
	return s, nil
}

// exportRSAPublicKey returns the public half of a CNG key handle. It performs the usual two-call
// NCryptExportKey sequence: ask for the blob size, then fill a buffer of that size.
func exportRSAPublicKey(hKey windows.Handle) (*rsa.PublicKey, error) {
	blobType, err := windows.UTF16PtrFromString(rsaPublicBlobType)
	if err != nil {
		return nil, fmt.Errorf("ncryptsigner: %w", err)
	}

	var size uint32
	status, _, _ := syscall.SyscallN(procNCryptExportKey.Addr(),
		uintptr(hKey), 0, uintptr(unsafe.Pointer(blobType)), 0,
		0, 0, uintptr(unsafe.Pointer(&size)), 0,
	)
	runtime.KeepAlive(blobType)
	if status != errorSuccessSecurity {
		return nil, ncryptError("NCryptExportKey(size)", status)
	}
	if size == 0 {
		return nil, fmt.Errorf("ncryptsigner: NCryptExportKey reported an empty key blob")
	}

	blob := make([]byte, size)
	status, _, _ = syscall.SyscallN(procNCryptExportKey.Addr(),
		uintptr(hKey), 0, uintptr(unsafe.Pointer(blobType)), 0,
		uintptr(unsafe.Pointer(&blob[0])), uintptr(size),
		uintptr(unsafe.Pointer(&size)), 0,
	)
	runtime.KeepAlive(blobType)
	if status != errorSuccessSecurity {
		return nil, ncryptError("NCryptExportKey", status)
	}
	// The second call rewrites size with the number of bytes it actually wrote, which must not
	// exceed the buffer it was given.
	if int(size) > len(blob) {
		return nil, fmt.Errorf("ncryptsigner: NCryptExportKey reported %d bytes written into a %d-byte buffer",
			size, len(blob))
	}
	return parseRSAPublicBlob(blob[:size])
}

// parseRSAPublicBlob decodes a BCRYPT_RSAKEY_BLOB that carries a public key. The layout is a
// six-ULONG little-endian header --
//
//	Magic, BitLength, cbPublicExp, cbModulus, cbPrime1, cbPrime2
//
// -- followed by the public exponent and then the modulus, both big-endian. A public blob leaves
// cbPrime1 and cbPrime2 zero and carries neither prime.
//
// Every declared length is checked against the buffer before it is used to slice it. The blob is
// data produced by another component, so treating its length fields as trustworthy would turn a
// provider bug into an out-of-range panic inside a TLS handshake.
func parseRSAPublicBlob(blob []byte) (*rsa.PublicKey, error) {
	if len(blob) < rsaKeyBlobHeaderLen {
		return nil, fmt.Errorf("ncryptsigner: key blob is %d bytes, too short for a BCRYPT_RSAKEY_BLOB",
			len(blob))
	}
	if magic := binary.LittleEndian.Uint32(blob[0:4]); magic != bcryptRSAPublicMagic {
		return nil, fmt.Errorf("ncryptsigner: key blob magic 0x%08X is not BCRYPT_RSAPUBLIC_MAGIC (0x%08X)",
			magic, uint32(bcryptRSAPublicMagic))
	}
	cbPublicExp := binary.LittleEndian.Uint32(blob[8:12])
	cbModulus := binary.LittleEndian.Uint32(blob[12:16])
	if cbPublicExp == 0 || cbModulus == 0 {
		return nil, fmt.Errorf("ncryptsigner: key blob declares a %d-byte public exponent and a %d-byte modulus",
			cbPublicExp, cbModulus)
	}
	// computed in uint64 so the sum can't wrap before it is compared, including on a 32-bit build
	end := uint64(rsaKeyBlobHeaderLen) + uint64(cbPublicExp) + uint64(cbModulus)
	if end > uint64(len(blob)) {
		return nil, fmt.Errorf("ncryptsigner: key blob declares %d bytes of key material but is only %d bytes",
			end, len(blob))
	}
	expStart := uint64(rsaKeyBlobHeaderLen)
	modStart := expStart + uint64(cbPublicExp)
	e := new(big.Int).SetBytes(blob[expStart:modStart])
	// rsa.PublicKey.E is an int, so reject anything that wouldn't survive the conversion. 31 bits
	// keeps it positive and in range on a 32-bit build too.
	if e.BitLen() == 0 || e.BitLen() > 31 {
		return nil, fmt.Errorf("ncryptsigner: key blob's public exponent is %d bits, which doesn't fit an int",
			e.BitLen())
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(blob[modStart:end]), E: int(e.Int64())}, nil
}

func storeLocationFlag(storeLocation string) (uint32, error) {
	switch strings.ToLower(strings.ReplaceAll(storeLocation, " ", "")) {
	case "currentuser":
		return windows.CERT_SYSTEM_STORE_CURRENT_USER, nil
	case "localmachine":
		return windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, nil
	default:
		return 0, fmt.Errorf("ncryptsigner: unknown store location %q, want CurrentUser or LocalMachine", storeLocation)
	}
}

// parseThumbprint accepts the SHA-256 thumbprint in any of the shapes Windows tooling emits: bare
// hex, space-separated pairs (certmgr's Details tab), or colon-separated pairs.
func parseThumbprint(thumbprint string) ([]byte, error) {
	cleaned := strings.NewReplacer(" ", "", ":", "", "-", "").Replace(strings.TrimSpace(thumbprint))
	if cleaned == "" {
		return nil, fmt.Errorf("ncryptsigner: thumbprint can't be empty")
	}
	raw, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("ncryptsigner: bad thumbprint %q: %w", thumbprint, err)
	}
	// A 20-byte value is a SHA-1 thumbprint, which is what every Windows surface hands out:
	// certmgr's Details tab, the Cert: drive's path, and $cert.Thumbprint all show SHA-1. It is
	// the overwhelmingly likely first thing a caller pastes, so name it and give the one-liner
	// that converts it instead of reporting a bare length mismatch.
	if len(raw) == sha1ThumbprintLen {
		return nil, fmt.Errorf("ncryptsigner: %q looks like a SHA-1 thumbprint; this sample identifies "+
			"certificates by SHA-256 thumbprint because SHA-1 is collision-prone. Get the SHA-256 value with: "+
			`(Get-Item Cert:\CurrentUser\My\%s).GetCertHashString('SHA256')`,
			thumbprint, strings.ToUpper(cleaned))
	}
	if len(raw) != sha256ThumbprintLen {
		return nil, fmt.Errorf("ncryptsigner: thumbprint must be a %d-byte SHA-256 hash, got %d bytes",
			sha256ThumbprintLen, len(raw))
	}
	return raw, nil
}

// derFromContext copies the encoded certificate out of a CERT_CONTEXT into Go memory, so the result
// outlives the context.
func derFromContext(ctx *windows.CertContext) []byte {
	der := make([]byte, ctx.Length)
	copy(der, unsafe.Slice(ctx.EncodedCert, ctx.Length))
	return der
}

// buildChain returns the DER chain for the certificate ctx refers to, leaf first, with intermediates
// included and a self-signed root omitted.
//
// It never fails the caller: when a chain can't be built it returns the leaf alone plus the reason,
// because a leaf-only x5c is still usable and refusing to open the signer would be a worse outcome
// than a narrower chain. Callers that require intermediates should check the returned error (see
// [Signer.ChainError]).
func buildChain(ctx *windows.CertContext, additionalStore windows.Handle, leafDER []byte) ([][]byte, error) {
	leafOnly := [][]byte{leafDER}

	para := windows.CertChainPara{URLRetrievalTimeout: chainURLRetrievalTimeoutMs}
	para.Size = uint32(unsafe.Sizeof(para))

	var chainCtx *windows.CertChainContext
	// A zeroed RequestedUsage means "no EKU filtering" and flags 0 means no revocation checking:
	// this call is only used to discover issuers, never to decide trust. additionalStore lets
	// intermediates that were imported alongside the leaf (the usual PFX case) be found even when
	// they aren't in the machine's CA store.
	err := windows.CertGetCertificateChain(0, ctx, nil, additionalStore, &para, 0, 0, &chainCtx)
	runtime.KeepAlive(&para)
	if err != nil {
		return leafOnly, fmt.Errorf("ncryptsigner: CertGetCertificateChain failed, "+
			"falling back to a leaf-only chain (x5c will carry no intermediates): %w", err)
	}
	defer windows.CertFreeCertificateChain(chainCtx)

	if chainCtx.ChainCount == 0 {
		return leafOnly, fmt.Errorf("ncryptsigner: CertGetCertificateChain returned no chains, " +
			"falling back to a leaf-only chain")
	}
	simple := unsafe.Slice(chainCtx.Chains, chainCtx.ChainCount)[0]
	if simple == nil || simple.NumElements == 0 {
		return leafOnly, fmt.Errorf("ncryptsigner: CertGetCertificateChain returned an empty chain, " +
			"falling back to a leaf-only chain")
	}
	elements := unsafe.Slice(simple.Elements, simple.NumElements)

	chain := make([][]byte, 0, len(elements))
	for i, element := range elements {
		if element == nil || element.CertContext == nil {
			return leafOnly, fmt.Errorf("ncryptsigner: chain element %d is empty, "+
				"falling back to a leaf-only chain", i)
		}
		elementDER := derFromContext(element.CertContext)
		if i == 0 {
			// Element 0 has to be the certificate that was asked for; anything else means the chain
			// engine resolved a different certificate, and that chain can't be trusted to describe
			// this key.
			if !bytes.Equal(elementDER, leafDER) {
				return leafOnly, fmt.Errorf("ncryptsigner: chain does not start with the requested " +
					"certificate, falling back to a leaf-only chain")
			}
			chain = append(chain, leafDER)
			continue
		}
		cert, err := x509.ParseCertificate(elementDER)
		if err != nil {
			return leafOnly, fmt.Errorf("ncryptsigner: parsing chain element %d failed, "+
				"falling back to a leaf-only chain: %w", i, err)
		}
		// Stop at a self-signed certificate: that's the root, and x5c carries leaf plus
		// intermediates only. Entra already trusts the root and doesn't need it on the wire.
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			break
		}
		chain = append(chain, elementDER)
	}
	return chain, nil
}
