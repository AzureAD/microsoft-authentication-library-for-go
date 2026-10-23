// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package certutil contains certificate ownership helpers shared by MSAL internals.
package certutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// CloneTLSCertificate returns a complete, independently mutable copy of cert.
//
// PrivateKey is intentionally shared because non-exportable crypto.Signer implementations cannot
// be copied. Every mutable slice is copied, and Leaf is parsed from the copied leaf DER so none of
// its Raw fields aliases either the caller's certificate or another MSAL-owned copy.
func CloneTLSCertificate(cert *tls.Certificate) (*tls.Certificate, error) {
	if cert == nil {
		return nil, errors.New("certificate is nil")
	}
	if len(cert.Certificate) == 0 || len(cert.Certificate[0]) == 0 {
		return nil, errors.New("certificate carries no certificate chain")
	}

	out := *cert
	out.Certificate = cloneByteSlices(cert.Certificate)
	out.SupportedSignatureAlgorithms = append([]tls.SignatureScheme(nil), cert.SupportedSignatureAlgorithms...)
	out.OCSPStaple = append([]byte(nil), cert.OCSPStaple...)
	out.SignedCertificateTimestamps = cloneByteSlices(cert.SignedCertificateTimestamps)

	leaf, err := x509.ParseCertificate(out.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("certificate leaf could not be parsed: %w", err)
	}
	out.Leaf = leaf
	return &out, nil
}

func cloneByteSlices(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i, b := range in {
		out[i] = append([]byte(nil), b...)
	}
	return out
}
