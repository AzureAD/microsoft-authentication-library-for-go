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
	NCRYPT_MACHINE_KEY_FLAG   = 0x00000020
	NCRYPT_OVERWRITE_KEY_FLAG = 0x00000080
	NCRYPT_ALLOW_EXPORT_NONE  = 0x00000001
	NCRYPT_SILENT_FLAG        = 0x00000040
)

var (
	ncrypt                    = syscall.NewLazyDLL("ncrypt.dll")
	procNCryptOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptOpenKey         = ncrypt.NewProc("NCryptOpenKey")
	procNCryptCreatePersistedKey = ncrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptSetProperty     = ncrypt.NewProc("NCryptSetProperty")
	procNCryptFinalizeKey     = ncrypt.NewProc("NCryptFinalizeKey")
	procNCryptExportKey       = ncrypt.NewProc("NCryptExportKey")
	procNCryptSignHash        = ncrypt.NewProc("NCryptSignHash")
	procNCryptFreeObject      = ncrypt.NewProc("NCryptFreeObject")
)

// cngSigner implements crypto.Signer using a CNG key handle.
type cngSigner struct {
	hKey   uintptr
	pubKey *rsa.PublicKey
}

func (s *cngSigner) Public() crypto.PublicKey {
	return s.pubKey
}

func (s *cngSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Use PKCS1v15 padding flags for RSA signing
	// BCRYPT_PAD_PKCS1 = 0x00000002
	paddingFlags := uint32(0x00000002)

	// Get required buffer size
	var sigLen uint32
	ret, _, _ := procNCryptSignHash.Call(
		s.hKey,
		0,
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
		0,
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

// GetOrCreateKeyGuardKey gets or creates a persistent KeyGuard RSA key in the CNG provider.
// Returns a crypto.Signer whose Sign method delegates to CNG.
func GetOrCreateKeyGuardKey(keyName string) (crypto.Signer, error) {
	keyNameUTF16, err := syscall.UTF16PtrFromString(keyName)
	if err != nil {
		return nil, fmt.Errorf("invalid key name: %w", err)
	}

	// Try Microsoft Platform Crypto Provider (uses VBS KeyGuard)
	providerName := "Microsoft Platform Crypto Provider"
	hProvider, err := openStorageProvider(providerName)
	if err != nil {
		// Fall back to Software Key Storage Provider
		providerName = "Microsoft Software Key Storage Provider"
		hProvider, err = openStorageProvider(providerName)
		if err != nil {
			return nil, fmt.Errorf("NCryptOpenStorageProvider failed: %w", err)
		}
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

	if ret != 0 {
		// Key not found — create it
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

		// Set export policy to disallow export
		if err := setDWORDProperty(hKey, "Export Policy", NCRYPT_ALLOW_EXPORT_NONE); err != nil {
			procNCryptFreeObject.Call(hKey)
			return nil, fmt.Errorf("set Export Policy property: %w", err)
		}

		// Finalize the key
		ret, _, _ = procNCryptFinalizeKey.Call(hKey, uintptr(NCRYPT_SILENT_FLAG))
		if ret != 0 {
			procNCryptFreeObject.Call(hKey)
			return nil, fmt.Errorf("NCryptFinalizeKey failed: 0x%x", ret)
		}
	}

	pubKey, err := exportPublicKey(hKey)
	if err != nil {
		procNCryptFreeObject.Call(hKey)
		return nil, fmt.Errorf("export public key: %w", err)
	}

	return &cngSigner{hKey: hKey, pubKey: pubKey}, nil
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
