// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// nonExportableSigner wraps a private key and exposes ONLY the crypto.Signer surface: Public() and
// Sign(). It deliberately provides no accessor for the underlying key, so once a key is wrapped there
// is no way to retrieve the private material through this type. This is the exact API shape a
// KeyGuard, TPM or HSM key presents in Go — the key lives behind an opaque signer — except that here
// the key is an ordinary software RSA key so the demo runs anywhere with no special hardware.
type nonExportableSigner struct {
	// key is unexported and never surfaced; the only operations offered are Public and Sign.
	key *rsa.PrivateKey
}

func (s nonExportableSigner) Public() crypto.PublicKey {
	return s.key.Public()
}

func (s nonExportableSigner) Sign(rn io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(rn, digest, opts)
}

var _ crypto.Signer = nonExportableSigner{}

// runSigner demonstrates PR #647/#649: NewCredFromTLSCertificate with a crypto.Signer whose private
// key is never exported. It builds a self-signed leaf, wraps its key in nonExportableSigner, and uses
// the resulting tls.Certificate to complete a client-certificate handshake against a local httptest
// TLS server that requires one. No network, lab, or special hardware is needed, so this runs offline.
func runSigner(args []string) error {
	fs := flag.NewFlagSet("signer", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	section("Signer-backed credential over mTLS (PR #647/#649)")
	fmt.Println("  Demonstrating a crypto.Signer whose private key is never exported.")

	// Generate a software RSA key and a self-signed certificate for it. In production the key would
	// live in KeyGuard/TPM/HSM; here it is software so the demo is portable, but we still only ever
	// hand MSAL the signer, never the key.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating the demo RSA key failed: %w", err)
	}
	leafDER, err := selfSignedLeaf(key)
	if err != nil {
		return err
	}

	signer := nonExportableSigner{key: key}
	kv("signer type", fmt.Sprintf("%T (crypto.Signer only)", signer))
	kv("signer.Public() type", fmt.Sprintf("%T", signer.Public()))

	// The tls.Certificate carries the DER chain and the OPAQUE signer as its PrivateKey. MSAL never
	// sees an *rsa.PrivateKey.
	clientTLSCert := tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  signer,
	}

	// NewCredFromTLSCertificate accepts the signer-backed certificate. This is the credential a
	// KeyGuard/HSM caller builds; MSAL adds no platform-specific dependency.
	cred, err := confidential.NewCredFromTLSCertificate(clientTLSCert)
	if err != nil {
		return fmt.Errorf("NewCredFromTLSCertificate failed: %w", err)
	}
	// A confidential client can be constructed from it. We do not send a token request (that needs a
	// real authority); the handshake below exercises the same signer MSAL would use on the mTLS leg.
	if _, err := confidential.New("https://login.microsoftonline.com/common", "11111111-1111-1111-1111-111111111111", cred); err != nil {
		return fmt.Errorf("confidential.New with the signer-backed credential failed: %w", err)
	}
	fmt.Println("  Built a confidential client from the signer-backed credential (no private key exported).")

	// Stand up a local TLS server that REQUIRES a client certificate, then present the signer-backed
	// certificate to it. A successful handshake proves crypto/tls signed the handshake through the
	// opaque signer — exactly what happens on MSAL's mutual-TLS leg.
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return fmt.Errorf("parsing the demo leaf failed: %w", err)
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(leaf)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}))
	server.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAs,
		MinVersion: tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	// Trust the server's own certificate, and present our signer-backed client certificate.
	serverCAs := x509.NewCertPool()
	serverCAs.AddCert(server.Certificate())
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      serverCAs,
				Certificates: []tls.Certificate{clientTLSCert},
				MinVersion:   tls.VersionTLS12,
			},
		},
	}

	section("client-certificate handshake against a local TLS server")
	resp, err := client.Get(server.URL)
	if err != nil {
		return fmt.Errorf("the mutual-TLS handshake with the signer-backed certificate failed: %w", err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err != nil {
		return fmt.Errorf("reading the response failed: %w", err)
	}

	kv("negotiated TLS version", tlsVersionName(resp.TLS.Version))
	kv("HTTP status", resp.Status)
	fmt.Println("  OK: the server required a client certificate and the handshake succeeded.")
	fmt.Println("  crypto/tls signed the handshake through the opaque signer; the private key never left it.")
	return nil
}

// selfSignedLeaf builds a minimal self-signed certificate for key and returns its DER bytes.
func selfSignedLeaf(key *rsa.PrivateKey) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "msal-go mtls signer demo"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("creating the self-signed certificate failed: %w", err)
	}
	return der, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
