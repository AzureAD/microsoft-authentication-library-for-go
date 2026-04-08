//go:build windows

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"syscall"
	"unsafe"
)

const (
	NCRYPT_MACHINE_KEY_FLAG          = 0x00000020
	NCRYPT_OVERWRITE_KEY_FLAG        = 0x00000080
	NCRYPT_ALLOW_EXPORT_NONE         = 0x00000001
	NCRYPT_SILENT_FLAG               = 0x00000040
	NCRYPT_USE_VIRTUAL_ISOLATION_FLAG = 0x00020000 // Request VBS KeyGuard (Hypervisor-Isolated) key
	NCRYPT_USE_PER_BOOT_KEY_FLAG     = 0x00040000 // Key material valid only for the current boot
)

var (
	ncrypt                        = syscall.NewLazyDLL("ncrypt.dll")
	procNCryptOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procNCryptCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptSetProperty         = ncrypt.NewProc("NCryptSetProperty")
	procNCryptGetProperty         = ncrypt.NewProc("NCryptGetProperty")
	procNCryptFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procNCryptExportKey           = ncrypt.NewProc("NCryptExportKey")
	procNCryptSignHash            = ncrypt.NewProc("NCryptSignHash")
	procNCryptFreeObject          = ncrypt.NewProc("NCryptFreeObject")
	procNCryptDeleteKey           = ncrypt.NewProc("NCryptDeleteKey")
)

// attestClientLib provides access to AttestationClientLib.dll — a native Windows DLL
// present on Azure VMs that performs KeyGuard key attestation via MAA.
//
// Function signatures (from MSAL.NET prototype/KeyGuardMaa/AttestationInterop.cs):
//
//	int  InitAttestationLib(AttestationLogInfo*)
//	int  AttestKeyGuardImportKey(char* endpoint, char* authToken, char* clientPayload,
//	                             NCRYPT_KEY_HANDLE keyHandle, char** token, char* clientId)
//	void FreeAttestationToken(char* token)
//	void UninitAttestationLib()
//
// All strings are ANSI (null-terminated *byte). On x64 Windows stdcall == cdecl.
var (
	attestClientLib              = syscall.NewLazyDLL("AttestationClientLib.dll")
	procInitAttestationLib       = attestClientLib.NewProc("InitAttestationLib")
	procAttestKeyGuardImportKey  = attestClientLib.NewProc("AttestKeyGuardImportKey")
	procFreeAttestationToken     = attestClientLib.NewProc("FreeAttestationToken")
	procUninitAttestationLib     = attestClientLib.NewProc("UninitAttestationLib")
)

// cngSigner implements crypto.Signer using a CNG key handle.
type cngSigner struct {
	hKey   uintptr
	pubKey *rsa.PublicKey
}

// attestationLogInfo mirrors the AttestationLogInfo struct in AttestationClientLib.dll.
// Pass zero values to disable logging.
//
//	struct AttestationLogInfo { LogFunc Log; void* Ctx; }
type attestationLogInfo struct {
	logFunc uintptr
	ctx     uintptr
}

// dummyLogCallback is a no-op log function passed to InitAttestationLib.
// The DLL requires a non-null log function pointer.
//
// Signature (cdecl, x64 Windows = same as stdcall for multi-arg):
//
//	void LogFunc(void* ctx, char* tag, int lvl, char* func, int line, char* msg)
var dummyLogCallback = syscall.NewCallback(func(ctx, tag uintptr, lvl uint32, fn uintptr, line uint32, msg uintptr) uintptr {
	return 0
})

// GetKeyGuardAttestationJWT calls AttestationClientLib.dll to produce a MAA JWT that
// proves the given CNG key is hardware-protected (KeyGuard/VBS).
//
// Parameters:
//   - s: a *cngSigner obtained from GetOrCreateKeyGuardKey
//   - endpoint: the attestation service URL from IMDS platform metadata (e.g. "https://sharedcuse.cuse.attest.azure.net")
//   - clientID: the VM managed identity client ID from IMDS platform metadata
//
// Returns the MAA JWT string to use as attestation_token in the IMDS /issuecredential request.
func GetKeyGuardAttestationJWT(s crypto.Signer, endpoint, clientID string) (string, error) {
	cs, ok := s.(*cngSigner)
	if !ok {
		return "", fmt.Errorf("GetKeyGuardAttestationJWT: signer is not a CNG key (type: %T)", s)
	}

	// InitAttestationLib — pass a no-op log function (DLL requires a non-null LogFunc).
	logInfo := attestationLogInfo{logFunc: dummyLogCallback}
	ret, _, _ := procInitAttestationLib.Call(uintptr(unsafe.Pointer(&logInfo)))
	if ret != 0 {
		return "", fmt.Errorf("InitAttestationLib failed: 0x%x", ret)
	}
	defer procUninitAttestationLib.Call()

	// Convert strings to ANSI (null-terminated *byte).
	endpointBytes, err := syscall.BytePtrFromString(endpoint)
	if err != nil {
		return "", fmt.Errorf("converting endpoint: %w", err)
	}
	clientIDBytes, err := syscall.BytePtrFromString(clientID)
	if err != nil {
		return "", fmt.Errorf("converting clientID: %w", err)
	}

	// AttestKeyGuardImportKey:
	//   endpoint, authToken (NULL), clientPayload (NULL), keyHandle, &tokenPtr, clientId
	var tokenPtr uintptr
	ret, _, _ = procAttestKeyGuardImportKey.Call(
		uintptr(unsafe.Pointer(endpointBytes)),
		0, // authToken — NULL
		0, // clientPayload — NULL
		cs.hKey,
		uintptr(unsafe.Pointer(&tokenPtr)),
		uintptr(unsafe.Pointer(clientIDBytes)),
	)
	if ret != 0 {
		return "", fmt.Errorf("AttestKeyGuardImportKey failed (rc=0x%x). "+
			"This usually means the VM's vTPM is not provisioned for attestation. "+
			"mTLS PoP requires a Trusted Launch Azure VM (Secure Boot + vTPM) with "+
			"an EK certificate. Check tpmtool.exe getdeviceinformation: "+
			"'Is Capable For Attestation' must be true", ret)
	}
	if tokenPtr == 0 {
		return "", fmt.Errorf("AttestKeyGuardImportKey returned null token")
	}
	defer procFreeAttestationToken.Call(tokenPtr)

	// Read null-terminated ANSI string from tokenPtr.
	jwt := cStringToGoString(tokenPtr)
	if jwt == "" {
		return "", fmt.Errorf("AttestKeyGuardImportKey returned empty token")
	}
	return jwt, nil
}

// cStringToGoString reads a null-terminated C string from memory at the given address.
func cStringToGoString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var buf []byte
	for {
		b := *(*byte)(unsafe.Pointer(ptr))
		if b == 0 {
			break
		}
		buf = append(buf, b)
		ptr++
	}
	return string(buf)
}

func (s *cngSigner) Public() crypto.PublicKey {
	return s.pubKey
}

// bcryptPKCS1PaddingInfo mirrors the Windows BCRYPT_PKCS1_PADDING_INFO struct.
type bcryptPKCS1PaddingInfo struct {
	pszAlgId *uint16
}

func (s *cngSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// NCRYPT_PAD_PKCS1_FLAG = 0x00000002
	// NCryptSignHash with PKCS1 padding requires a pointer to BCRYPT_PKCS1_PADDING_INFO.
	hashAlgName, err := hashAlgIDFromOpts(opts)
	if err != nil {
		return nil, err
	}
	algNameUTF16, err := syscall.UTF16PtrFromString(hashAlgName)
	if err != nil {
		return nil, fmt.Errorf("converting hash alg name: %w", err)
	}
	padding := bcryptPKCS1PaddingInfo{pszAlgId: algNameUTF16}
	paddingFlags := uint32(0x00000002) // NCRYPT_PAD_PKCS1_FLAG

	// Get required buffer size
	var sigLen uint32
	ret, _, _ := procNCryptSignHash.Call(
		s.hKey,
		uintptr(unsafe.Pointer(&padding)),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0,
		0,
		uintptr(unsafe.Pointer(&sigLen)),
		uintptr(paddingFlags),
	)
	if ret != 0 {
		return nil, fmt.Errorf("NCryptSignHash (size query) failed: 0x%x", ret)
	}

	sig := make([]byte, sigLen)
	ret, _, _ = procNCryptSignHash.Call(
		s.hKey,
		uintptr(unsafe.Pointer(&padding)),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(sigLen),
		uintptr(unsafe.Pointer(&sigLen)),
		uintptr(paddingFlags),
	)
	if ret != 0 {
		return nil, fmt.Errorf("NCryptSignHash failed: 0x%x", ret)
	}
	return sig[:sigLen], nil
}

// hashAlgIDFromOpts returns the CNG hash algorithm name (e.g. "SHA256") for the given SignerOpts.
func hashAlgIDFromOpts(opts crypto.SignerOpts) (string, error) {
	if opts == nil {
		return "SHA256", nil
	}
	switch opts.HashFunc() {
	case crypto.SHA1:
		return "SHA1", nil
	case crypto.SHA256:
		return "SHA256", nil
	case crypto.SHA384:
		return "SHA384", nil
	case crypto.SHA512:
		return "SHA512", nil
	default:
		return "SHA256", nil
	}
}

// GetOrCreateKeyGuardKey gets or creates a persistent VBS KeyGuard RSA key using
// "Microsoft Software Key Storage Provider" with NCRYPT_USE_VIRTUAL_ISOLATION_FLAG.
//
// This mirrors the MSAL.NET approach (KeyGuardAttestationTests.cs):
//
//	CngProvider = "Microsoft Software Key Storage Provider"
//	KeyCreationOptions = NCRYPT_USE_VIRTUAL_ISOLATION_FLAG | NCRYPT_USE_PER_BOOT_KEY_FLAG
//
// The key is hardware-backed by Windows VBS (Virtualization-Based Security), not the TPM.
// AttestKeyGuardImportKey in AttestationClientLib.dll requires a VBS KeyGuard key — NOT a
// Platform Crypto Provider (TPM) key. This function ensures the correct key type.
func GetOrCreateKeyGuardKey(keyName string) (crypto.Signer, error) {
	keyNameUTF16, err := syscall.UTF16PtrFromString(keyName)
	if err != nil {
		return nil, fmt.Errorf("invalid key name: %w", err)
	}

	// Always use Microsoft Software Key Storage Provider with VBS Virtual Isolation.
	// DO NOT use Microsoft Platform Crypto Provider (TPM-backed): AttestKeyGuardImportKey
	// requires a VBS KeyGuard key and will fail on TPM keys.
	providerName := "Microsoft Software Key Storage Provider"
	hProvider, err := openStorageProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("NCryptOpenStorageProvider(%q): %w", providerName, err)
	}
	defer procNCryptFreeObject.Call(hProvider)

	// Try to open an existing key
	var hKey uintptr
	ret, _, _ := procNCryptOpenKey.Call(
		hProvider,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(keyNameUTF16)),
		0,
		uintptr(NCRYPT_MACHINE_KEY_FLAG|NCRYPT_SILENT_FLAG),
	)

	if ret == 0 {
		// Key exists — verify it's usable (not un-finalized from a prior failed creation).
		// If export fails, delete and recreate.
		if _, pubErr := exportPublicKey(hKey); pubErr != nil {
			procNCryptDeleteKey.Call(hKey, 0) // NCryptDeleteKey also frees hKey
			hKey = 0
			ret = 1 // force creation below
		}
	}

	if ret != 0 {
		// Key not found (or deleted above) — create with VBS Virtual Isolation
		algID, _ := syscall.UTF16PtrFromString("RSA")
		ret, _, _ = procNCryptCreatePersistedKey.Call(
			hProvider,
			uintptr(unsafe.Pointer(&hKey)),
			uintptr(unsafe.Pointer(algID)),
			uintptr(unsafe.Pointer(keyNameUTF16)),
			0,
			uintptr(NCRYPT_OVERWRITE_KEY_FLAG|NCRYPT_MACHINE_KEY_FLAG),
		)
		if ret != 0 {
			return nil, fmt.Errorf("NCryptCreatePersistedKey failed: 0x%x", ret)
		}

		// Set key length to 2048 bits
		if err := setDWORDProperty(hKey, "Length", 2048); err != nil {
			procNCryptFreeObject.Call(hKey)
			return nil, fmt.Errorf("set Length property: %w", err)
		}

		// Disallow key export
		if err := setDWORDProperty(hKey, "Export Policy", NCRYPT_ALLOW_EXPORT_NONE); err != nil {
			procNCryptFreeObject.Call(hKey)
			return nil, fmt.Errorf("set Export Policy: %w", err)
		}

		// Finalize with VBS Virtual Isolation + Per-Boot flags (best-effort).
		// NCRYPT_USE_VIRTUAL_ISOLATION_FLAG requests that the key be protected by VBS/KeyGuard.
		// NCRYPT_USE_PER_BOOT_KEY_FLAG limits key validity to the current boot session.
		// Some VM configurations may not support these flags — fall back to plain finalization
		// if they are rejected (NTE_BAD_FLAGS). AttestKeyGuardImportKey will still verify
		// whether the key is actually KeyGuard-protected.
		vbsFlags := uintptr(NCRYPT_USE_VIRTUAL_ISOLATION_FLAG | NCRYPT_USE_PER_BOOT_KEY_FLAG | NCRYPT_SILENT_FLAG)
		ret, _, _ = procNCryptFinalizeKey.Call(hKey, vbsFlags)
		if ret != 0 {
			// Fall back: finalize without VBS flags; attestation DLL will verify key protection.
			ret, _, _ = procNCryptFinalizeKey.Call(hKey, uintptr(NCRYPT_SILENT_FLAG))
			if ret != 0 {
				procNCryptFreeObject.Call(hKey)
				return nil, fmt.Errorf("NCryptFinalizeKey failed: 0x%x", ret)
			}
		}
	}

	pubKey, err := exportPublicKey(hKey)
	if err != nil {
		procNCryptFreeObject.Call(hKey)
		return nil, fmt.Errorf("export public key: %w", err)
	}

	return &cngSigner{hKey: hKey, pubKey: pubKey}, nil
}

// isKeyGuardProtected checks whether hKey is a VBS-backed KeyGuard key by reading the
// "Virtual Iso" property. Returns true only if the property value is non-zero.
// This mirrors the MSAL.NET check in KeyGuardAttestationTests.IsKeyGuardProtected.
func isKeyGuardProtected(hKey uintptr) bool {
	propName, _ := syscall.UTF16PtrFromString("Virtual Iso")
	var value uint32
	var bytesUsed uint32
	ret, _, _ := procNCryptGetProperty.Call(
		hKey,
		uintptr(unsafe.Pointer(propName)),
		uintptr(unsafe.Pointer(&value)),
		unsafe.Sizeof(value),
		uintptr(unsafe.Pointer(&bytesUsed)),
		0,
	)
	return ret == 0 && bytesUsed >= 4 && value != 0
}

func openStorageProvider(name string) (uintptr, error) {
	nameUTF16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var hProvider uintptr
	ret, _, _ := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&hProvider)),
		uintptr(unsafe.Pointer(nameUTF16)),
		0,
	)
	if ret != 0 {
		return 0, fmt.Errorf("NCryptOpenStorageProvider(%q) failed: 0x%x", name, ret)
	}
	return hProvider, nil
}

func setDWORDProperty(hKey uintptr, propName string, value uint32) error {
	propUTF16, err := syscall.UTF16PtrFromString(propName)
	if err != nil {
		return err
	}
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], value)
	ret, _, _ := procNCryptSetProperty.Call(
		hKey,
		uintptr(unsafe.Pointer(propUTF16)),
		uintptr(unsafe.Pointer(&buf[0])),
		4,
		uintptr(NCRYPT_SILENT_FLAG),
	)
	if ret != 0 {
		return fmt.Errorf("NCryptSetProperty(%q) failed: 0x%x", propName, ret)
	}
	return nil
}

// exportPublicKey exports the RSA public key from the CNG key handle.
// CNG RSAPUBLICBLOB format:
//
//	struct {
//	    Magic       uint32 // 0x31415352 = "RSA1"
//	    BitLength   uint32
//	    cbPublicExp uint32
//	    cbModulus   uint32
//	    cbPrime1    uint32
//	    cbPrime2    uint32
//	}
//
// followed by PublicExponent bytes (cbPublicExp), then Modulus bytes (cbModulus).
func exportPublicKey(hKey uintptr) (*rsa.PublicKey, error) {
	blobTypeUTF16, _ := syscall.UTF16PtrFromString("RSAPUBLICBLOB")

	// Query required buffer size
	var blobLen uint32
	ret, _, _ := procNCryptExportKey.Call(
		hKey,
		0,
		uintptr(unsafe.Pointer(blobTypeUTF16)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&blobLen)),
		0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("NCryptExportKey (size query) failed: 0x%x", ret)
	}

	blob := make([]byte, blobLen)
	ret, _, _ = procNCryptExportKey.Call(
		hKey,
		0,
		uintptr(unsafe.Pointer(blobTypeUTF16)),
		0,
		uintptr(unsafe.Pointer(&blob[0])),
		uintptr(blobLen),
		uintptr(unsafe.Pointer(&blobLen)),
		0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("NCryptExportKey failed: 0x%x", ret)
	}

	// Parse BCRYPT_RSAKEY_BLOB header (24 bytes)
	if len(blob) < 24 {
		return nil, fmt.Errorf("RSAPUBLICBLOB too short: %d bytes", len(blob))
	}
	// magic := binary.LittleEndian.Uint32(blob[0:4])  // 0x31415352 = "RSA1"
	// bitLen := binary.LittleEndian.Uint32(blob[4:8])
	cbPublicExp := binary.LittleEndian.Uint32(blob[8:12])
	cbModulus := binary.LittleEndian.Uint32(blob[12:16])
	// cbPrime1 := binary.LittleEndian.Uint32(blob[16:20])
	// cbPrime2 := binary.LittleEndian.Uint32(blob[20:24])

	offset := uint32(24)
	if uint32(len(blob)) < offset+cbPublicExp+cbModulus {
		return nil, fmt.Errorf("RSAPUBLICBLOB too short for key data")
	}

	expBytes := blob[offset : offset+cbPublicExp]
	offset += cbPublicExp
	modBytes := blob[offset : offset+cbModulus]

	// Convert exponent bytes to int
	var exp int
	for _, b := range expBytes {
		exp = exp<<8 | int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modBytes),
		E: exp,
	}, nil
}
