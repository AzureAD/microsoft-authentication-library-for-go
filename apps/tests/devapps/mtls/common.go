// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// Known-good lab defaults, proven by #632's passing integration tests in
// apps/tests/integration/mtls_pop_integration_test.go. They are public identifiers, not secrets, and
// every one is overridable with a flag or environment variable (see config).
const (
	defaultClientID  = "163ffef9-a313-45b4-ab2f-c7e2f5e0e23e"
	defaultAuthority = "https://login.microsoftonline.com/bea21ebe-8b64-4d06-9f6d-6a889b120a7c"
	defaultRegion    = "westus3"
	defaultPoPScope  = "https://vault.azure.net/.default"

	// tokenExchangeScope is the audience the first leg of a two-leg S2S FIC exchange requests: it
	// yields a federated assertion rather than a resource token. Mirrors MSAL .NET's TokenExchangeUrl.
	tokenExchangeScope = "api://AzureADTokenExchange/.default"
)

// config holds the values common to every subcommand. Each subcommand registers these flags on its
// own flag.FlagSet so `mtls <cmd> -h` lists exactly what that command accepts.
type config struct {
	clientID  string
	authority string
	region    string
	certPath  string
	scope     string
}

// loadCertificate reads a PEM file (certificate + private key) and builds a NewCredFromCert
// credential from it, exactly the way apps/tests/integration/config_helpers_test.go's
// getCertDataFromFile does. It returns the parsed leaf certificate too, so callers can compute the
// x5t#S256 thumbprint themselves. No certificate, key or secret is ever embedded or logged.
func loadCertificate(certPath string) (confidential.Credential, *x509.Certificate, error) {
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

// cnfThumbprintFromToken decodes an access token's JWT body and returns its cnf["x5t#S256"] claim, the
// thumbprint of the certificate the token is bound to. It reuses the approach in
// apps/tests/integration/mtls_pop_integration_test.go's checkTokenBoundToCertificate. It returns an
// empty string (not an error) when the token carries no such claim, so callers can report "unbound".
func cnfThumbprintFromToken(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("access token is not a JWT: got %d segments, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decoding the JWT payload failed: %w", err)
	}
	var claims struct {
		Cnf map[string]string `json:"cnf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("parsing the JWT payload failed: %w", err)
	}
	return claims.Cnf["x5t#S256"], nil
}

// thumbprintOfCert returns the base64url-encoded SHA-256 thumbprint (x5t#S256) of a certificate, the
// value that appears in an mtls_pop token's cnf claim.
func thumbprintOfCert(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// section prints a labelled banner so projected output is easy to follow on a screen.
func section(title string) {
	fmt.Println()
	fmt.Println("== " + title + " ==")
}

// kv prints an aligned "key: value" line.
func kv(key, value string) {
	fmt.Printf("  %-32s %s\n", key+":", value)
}

// env returns the environment variable value if set, otherwise def.
func env(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

// registerCommonFlags wires the flags shared by the network subcommands onto fs, seeding defaults from
// environment variables so the demo works with zero flags in the known-good lab, yet stays fully
// overridable. It does not register -scope; each subcommand sets its own scope default.
func registerCommonFlags(fs *flag.FlagSet, cfg *config) {
	fs.StringVar(&cfg.clientID, "client-id", env("MTLS_CLIENT_ID", defaultClientID), "application (client) ID")
	fs.StringVar(&cfg.authority, "authority", env("MTLS_AUTHORITY", defaultAuthority), "authority URL (must be tenanted for mTLS PoP)")
	fs.StringVar(&cfg.region, "region", env("MTLS_REGION", defaultRegion), "Azure region for the regional token endpoint (empty to disable)")
	fs.StringVar(&cfg.certPath, "cert", env("MTLS_CERT_PATH", ""), "path to a PEM file with the SN/I certificate and its private key")
}
