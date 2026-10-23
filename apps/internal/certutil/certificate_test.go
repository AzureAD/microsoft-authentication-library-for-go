// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package certutil

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestCloneTLSCertificateCopiesAllMutableFields(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "clone test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	source := &tls.Certificate{
		Certificate:                  [][]byte{append([]byte(nil), der...), {1, 2, 3}},
		PrivateKey:                   key,
		Leaf:                         leaf,
		SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.PKCS1WithSHA256},
		OCSPStaple:                   []byte{4, 5, 6},
		SignedCertificateTimestamps:  [][]byte{{7, 8}, {9, 10}},
	}
	got, err := CloneTLSCertificate(source)
	if err != nil {
		t.Fatal(err)
	}
	if got.PrivateKey != source.PrivateKey {
		t.Error("PrivateKey wasn't shared")
	}
	if got.Leaf == source.Leaf {
		t.Fatal("Leaf was shared")
	}

	wantDER := append([]byte(nil), got.Certificate[0]...)
	wantAlgorithms := append([]tls.SignatureScheme(nil), got.SupportedSignatureAlgorithms...)
	wantStaple := append([]byte(nil), got.OCSPStaple...)
	wantSCT := append([]byte(nil), got.SignedCertificateTimestamps[0]...)

	source.Certificate[0][0] ^= 0xff
	source.Certificate[1][0] ^= 0xff
	source.Leaf.Raw[0] ^= 0xff
	source.SupportedSignatureAlgorithms[0] = tls.PSSWithSHA256
	source.OCSPStaple[0] ^= 0xff
	source.SignedCertificateTimestamps[0][0] ^= 0xff

	if !bytes.Equal(got.Certificate[0], wantDER) || !bytes.Equal(got.Leaf.Raw, wantDER) {
		t.Error("DER or Leaf.Raw aliases the source")
	}
	if got.SupportedSignatureAlgorithms[0] != wantAlgorithms[0] {
		t.Error("SupportedSignatureAlgorithms aliases the source")
	}
	if !bytes.Equal(got.OCSPStaple, wantStaple) {
		t.Error("OCSPStaple aliases the source")
	}
	if !bytes.Equal(got.SignedCertificateTimestamps[0], wantSCT) {
		t.Error("SignedCertificateTimestamps entry aliases the source")
	}
}
