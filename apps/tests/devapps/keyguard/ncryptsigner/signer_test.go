//go:build windows

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package ncryptsigner

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
)

// rsaPublicBlob builds the BCRYPT_RSAKEY_BLOB CNG returns for a public key, so the parser can be
// tested without a key store. Layout: six little-endian ULONGs (Magic, BitLength, cbPublicExp,
// cbModulus, cbPrime1, cbPrime2) followed by the big-endian exponent and then the big-endian
// modulus. A public blob carries no primes.
func rsaPublicBlob(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	e := big.NewInt(int64(pub.E)).Bytes()
	n := pub.N.Bytes()
	blob := make([]byte, rsaKeyBlobHeaderLen+len(e)+len(n))
	binary.LittleEndian.PutUint32(blob[0:4], bcryptRSAPublicMagic)
	binary.LittleEndian.PutUint32(blob[4:8], uint32(pub.N.BitLen()))
	binary.LittleEndian.PutUint32(blob[8:12], uint32(len(e)))
	binary.LittleEndian.PutUint32(blob[12:16], uint32(len(n)))
	copy(blob[rsaKeyBlobHeaderLen:], e)
	copy(blob[rsaKeyBlobHeaderLen+len(e):], n)
	return blob
}

func TestParseRSAPublicBlob(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	blob := rsaPublicBlob(t, &key.PublicKey)

	got, err := parseRSAPublicBlob(blob)
	if err != nil {
		t.Fatalf("parseRSAPublicBlob on a well-formed blob: %v", err)
	}
	if !key.PublicKey.Equal(got) {
		t.Fatal("the parsed key isn't the key the blob encodes")
	}
}

// TestParseRSAPublicBlobRejects covers the hostile cases. The blob is produced by another component,
// so a length field that disagrees with the buffer has to be an error rather than an out-of-range
// panic in the middle of a TLS handshake.
func TestParseRSAPublicBlobRejects(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	good := rsaPublicBlob(t, &key.PublicKey)

	// mutate returns an independent copy of good with f applied, so each case gets a slice whose
	// capacity matches its length; a sub-slice of good would still permit reads past its length.
	mutate := func(f func([]byte) []byte) []byte {
		cp := make([]byte, len(good))
		copy(cp, good)
		return f(cp)
	}

	for _, test := range []struct {
		name string
		blob []byte
	}{
		{"empty", []byte{}},
		{"one byte", mutate(func(b []byte) []byte { return b[:1:1] })},
		{"header truncated by one byte", mutate(func(b []byte) []byte { return b[: rsaKeyBlobHeaderLen-1 : rsaKeyBlobHeaderLen-1] })},
		{"header only", mutate(func(b []byte) []byte { return b[:rsaKeyBlobHeaderLen:rsaKeyBlobHeaderLen] })},
		{"key material short by one byte", mutate(func(b []byte) []byte { return b[: len(b)-1 : len(b)-1] })},
		{"private blob magic", mutate(func(b []byte) []byte {
			// BCRYPT_RSAPRIVATE_MAGIC, i.e. a blob that carries more than a public key
			binary.LittleEndian.PutUint32(b[0:4], 0x32415352)
			return b
		})},
		{"zero magic", mutate(func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[0:4], 0)
			return b
		})},
		{"zero-length exponent", mutate(func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[8:12], 0)
			return b
		})},
		{"zero-length modulus", mutate(func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[12:16], 0)
			return b
		})},
		{"modulus longer than the buffer", mutate(func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[12:16], 0xFFFFFFFF)
			return b
		})},
		{"exponent longer than the buffer", mutate(func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[8:12], 0xFFFFFFFF)
			return b
		})},
		{"lengths that would overflow a 32-bit sum", mutate(func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[8:12], 0xFFFFFFF0)
			binary.LittleEndian.PutUint32(b[12:16], 0xFFFFFFF0)
			return b
		})},
		{"exponent bytes are all zero", mutate(func(b []byte) []byte {
			cbExp := binary.LittleEndian.Uint32(b[8:12])
			for i := rsaKeyBlobHeaderLen; i < rsaKeyBlobHeaderLen+int(cbExp); i++ {
				b[i] = 0
			}
			return b
		})},
		{"exponent too large for an int", mutate(func(b []byte) []byte {
			// claim all but one byte of the payload is the exponent, which is far more than 31
			// bits, while leaving the modulus non-empty so this reaches the exponent check
			binary.LittleEndian.PutUint32(b[8:12], uint32(len(b)-rsaKeyBlobHeaderLen-1))
			binary.LittleEndian.PutUint32(b[12:16], 1)
			return b
		})},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseRSAPublicBlob panicked instead of returning an error: %v", r)
				}
			}()
			if _, err := parseRSAPublicBlob(test.blob); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// TestSignRejectsNegativeSaltLength pins the guard in Sign. A PSS salt length that is negative but is
// neither PSSSaltLengthAuto nor PSSSaltLengthEqualsHash has to be rejected before it reaches CNG:
// cbSalt is a uint32, so without the guard a SaltLength of -7 arrives as 4294967289. The assertion is
// on the specific message rather than merely "an error" because CNG returns an error here anyway, for
// its own reasons, which would make a bare non-nil check pass with or without the guard.
func TestSignRejectsNegativeSaltLength(t *testing.T) {
	var s Signer // the guard runs before any key handle is touched, so no key store is needed
	digest := make([]byte, crypto.SHA256.Size())
	_, err := s.Sign(nil, digest, &rsa.PSSOptions{SaltLength: -7, Hash: crypto.SHA256})
	if err == nil {
		t.Fatal("Sign() = nil error, want a rejection for a negative PSS salt length")
	}
	if !strings.Contains(err.Error(), "invalid PSS salt length -7") {
		t.Errorf("Sign() error = %v, want it to name the invalid salt length", err)
	}
}