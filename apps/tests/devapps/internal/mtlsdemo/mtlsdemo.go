// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package mtlsdemo provides shared configuration, certificate loading and display helpers for
// the mTLS demo programs added by PR #643 (bearerovermtls and mtlscacheisolation). A small
// overlap with sibling-PR demos such as mtlspop is left in place on purpose so each PR in the
// stack stays runnable on its own branch.
package mtlsdemo

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// Known-good lab defaults, matching the constants the passing integration tests use in
// apps/tests/integration/mtls_pop_integration_test.go. They are public identifiers, not secrets, and
// every one is overridable with a flag or an environment variable.
const (
	DefaultClientID  = "163ffef9-a313-45b4-ab2f-c7e2f5e0e23e"
	DefaultAuthority = "https://login.microsoftonline.com/bea21ebe-8b64-4d06-9f6d-6a889b120a7c"
	DefaultRegion    = "westus3"
	DefaultScope     = "https://vault.azure.net/.default"
)

// LoadCertificate reads a PEM file holding a certificate and its private key and builds a
// NewCredFromCert credential from it, the same way apps/tests/integration's getCertDataFromFile
// does. It also returns the parsed leaf so the caller can print its x5t#S256 thumbprint. No
// certificate, key or secret is ever embedded in this program or written to its output.
func LoadCertificate(certPath string) (confidential.Credential, *x509.Certificate, error) {
	if strings.TrimSpace(certPath) == "" {
		return confidential.Credential{}, nil, fmt.Errorf(
			"no certificate supplied: pass -cert <path-to-pem> or set MTLS_CERT_PATH to a PEM file " +
				"containing the SN/I certificate and its private key")
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		return confidential.Credential{}, nil, fmt.Errorf("reading certificate file %q failed: %w", certPath, err)
	}
	certs, privateKey, err := confidential.CertFromPEM(data, "")
	if err != nil {
		return confidential.Credential{}, nil, fmt.Errorf("parsing certificate PEM %q failed: %w", certPath, err)
	}
	if len(certs) == 0 {
		return confidential.Credential{}, nil, fmt.Errorf("certificate PEM %q contained no certificates", certPath)
	}
	cred, err := confidential.NewCredFromCert(certs, privateKey)
	if err != nil {
		return confidential.Credential{}, nil, fmt.Errorf("NewCredFromCert failed: %w", err)
	}
	return cred, certs[0], nil
}

// ThumbprintOfCert returns the base64url-encoded SHA-256 thumbprint (x5t#S256) of a certificate: the
// value MSAL uses as the mtls_pop cache entry's authentication-scheme key ID, and the value that
// appears in an mtls_pop token's cnf claim.
func ThumbprintOfCert(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TokenSourceName renders a TokenSource for display.
func TokenSourceName(s confidential.TokenSource) string {
	switch s {
	case confidential.TokenSourceCache:
		return "cache"
	case confidential.TokenSourceIdentityProvider:
		return "identity-provider"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// RegionLabel describes the configured region for display.
func RegionLabel(region string) string {
	if region == "" {
		return "<none - global mtlsauth endpoint>"
	}
	return region
}

// Section prints a labelled banner so the output is easy to follow on a screen.
func Section(title string) {
	fmt.Println()
	fmt.Println("== " + title + " ==")
}

// KV prints an aligned "key: value" line.
func KV(key, value string) {
	fmt.Printf("  %-32s %s\n", key+":", value)
}

// Env returns the environment variable's value when it is set to something non-blank, else def.
func Env(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}
