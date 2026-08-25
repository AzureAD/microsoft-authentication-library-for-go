// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Command bearerovermtls is a runnable demo of [confidential.WithSendCertificateOverMtls].
//
// The option makes a confidential client present its certificate credential as the client
// certificate on the mutual-TLS handshake to the token endpoint and routes the request to the mTLS
// endpoint (mtlsauth.*) — but the token that comes back is an ordinary, UNBOUND Bearer token. That
// contrast is the whole point of the demo:
//
//	WithMtlsProofOfPossession   -> token_type=mtls_pop, bound to the certificate. The resource
//	                               only accepts it over a connection that presents that same
//	                               certificate.
//	WithSendCertificateOverMtls -> token_type=Bearer, bound to nothing. The certificate
//	                               authenticated the *transport* to Entra ID; the token itself is
//	                               usable against the resource without any certificate.
//
// The demo prints the three independent pieces of evidence that the token is unbound:
// AuthResult.Metadata.TokenType is "Bearer", AuthResult.BindingCertificate is nil, and the decoded
// access token carries no cnf["x5t#S256"] confirmation claim. It then acquires a second time to
// show the token is cached under the ordinary Bearer cache key.
//
// Usage:
//
//	go run ./apps/tests/devapps/bearerovermtls -cert /path/to/sni-cert.pem
//
// See README.md in this directory for flags, environment variables and expected output.
package main

import (
	"context"
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

// The small config/printing/certificate helpers below are duplicated in each devapp under
// apps/tests/devapps rather than factored into a shared demo package. That is deliberate: a shared
// package would couple this demo to demos for sibling PRs, and each PR in the mTLS stack has to be
// reviewable — and runnable — on its own branch. Copying a few dozen lines is the cheaper trade.

// Known-good lab defaults, matching the constants the passing integration tests use in
// apps/tests/integration/mtls_pop_integration_test.go. They are public identifiers, not secrets, and
// every one is overridable with a flag or an environment variable.
const (
	defaultClientID  = "163ffef9-a313-45b4-ab2f-c7e2f5e0e23e"
	defaultAuthority = "https://login.microsoftonline.com/bea21ebe-8b64-4d06-9f6d-6a889b120a7c"
	defaultRegion    = "westus3"
	defaultScope     = "https://vault.azure.net/.default"
)

// config holds everything the demo needs to build a client.
type config struct {
	clientID  string
	authority string
	region    string
	certPath  string
	scope     string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "\nerror: %s\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("bearerovermtls", flag.ExitOnError)
	var cfg config
	fs.StringVar(&cfg.clientID, "client-id", env("MTLS_CLIENT_ID", defaultClientID), "application (client) ID")
	fs.StringVar(&cfg.authority, "authority", env("MTLS_AUTHORITY", defaultAuthority), "authority URL (must be tenanted)")
	fs.StringVar(&cfg.region, "region", env("MTLS_REGION", defaultRegion), "Azure region for the regional mtlsauth endpoint (empty to use the global one)")
	fs.StringVar(&cfg.certPath, "cert", env("MTLS_CERT_PATH", ""), "path to a PEM file holding the SN/I certificate and its private key")
	fs.StringVar(&cfg.scope, "scope", env("MTLS_SCOPE", defaultScope), "resource scope to request")
	if err := fs.Parse(args); err != nil {
		return err
	}

	section("configuration")
	kv("authority", cfg.authority)
	kv("client id", cfg.clientID)
	kv("region", regionLabel(cfg.region))
	kv("scope", cfg.scope)

	// This part needs neither a certificate nor the network, so it always runs and the demo prints
	// something useful even when it is invoked with no arguments at all.
	if err := showCredentialGuardrail(cfg); err != nil {
		return err
	}

	cred, leaf, err := loadCertificate(cfg.certPath)
	if err != nil {
		return err
	}
	section("certificate")
	kv("x5t#S256", thumbprintOfCert(leaf))

	// WithSendCertificateOverMtls is an APP-level option: it is passed to confidential.New, not to
	// the acquisition call. Every flow this client runs that sends a client credential -- client
	// credentials, on-behalf-of, authorization code and silent refresh -- goes over the mTLS
	// transport from here on. (AcquireTokenByUsernamePassword sends no client credential at all and
	// AcquireTokenByUserFederatedIdentityCredential is likewise excluded; both keep using the
	// regular token endpoint. This matches MSAL .NET's SendCertificateOverMtls.)
	app, err := buildClient(cfg, cred, confidential.WithSendCertificateOverMtls())
	if err != nil {
		return fmt.Errorf("confidential.New failed: %w", err)
	}

	ctx := context.Background()

	section("acquire")
	// Note what is NOT here: no per-request option. A per-request WithMtlsProofOfPossession would
	// take precedence over the app-level flag and produce a bound mtls_pop token instead.
	result, err := app.AcquireTokenByCredential(ctx, []string{cfg.scope})
	if err != nil {
		return fmt.Errorf("AcquireTokenByCredential over mTLS failed: %w", err)
	}
	kv("Metadata.TokenType", result.Metadata.TokenType)
	kv("Metadata.TokenSource", tokenSourceName(result.Metadata.TokenSource))
	if result.BindingCertificate == nil {
		kv("AuthResult.BindingCertificate", "<nil>")
	} else {
		kv("AuthResult.BindingCertificate", "<non-nil!>")
	}
	cnf, cnfReadable := cnfThumbprintFromToken(result.AccessToken)
	switch {
	case !cnfReadable:
		kv(`token cnf["x5t#S256"]`, "<access token is not an inspectable JWT>")
	case cnf == "":
		kv(`token cnf["x5t#S256"]`, "<absent - the token is unbound>")
	default:
		kv(`token cnf["x5t#S256"]`, cnf)
	}

	// A plain Bearer token is cached under the ordinary Bearer cache key, so a second call for the
	// same scope is served from the cache rather than from Entra ID.
	section("acquire again (same client, same scope)")
	cached, err := app.AcquireTokenByCredential(ctx, []string{cfg.scope})
	if err != nil {
		return fmt.Errorf("second AcquireTokenByCredential failed: %w", err)
	}
	kv("Metadata.TokenType", cached.Metadata.TokenType)
	kv("Metadata.TokenSource", tokenSourceName(cached.Metadata.TokenSource))
	kv("same access token as #1", fmt.Sprint(cached.AccessToken == result.AccessToken))

	section("verification")
	if result.Metadata.TokenType != "Bearer" {
		return fmt.Errorf("expected token_type Bearer, got %q", result.Metadata.TokenType)
	}
	fmt.Println(`  PASS  Metadata.TokenType == "Bearer" (not mtls_pop).`)

	if result.BindingCertificate != nil {
		return fmt.Errorf("expected a nil BindingCertificate on an unbound Bearer token")
	}
	fmt.Println("  PASS  AuthResult.BindingCertificate is nil - MSAL bound the token to nothing.")

	if cnfReadable && cnf != "" {
		return fmt.Errorf("unexpected cnf claim %q on a token that should be unbound", cnf)
	}
	if cnfReadable {
		fmt.Println(`  PASS  the token carries no cnf["x5t#S256"] confirmation claim.`)
	}

	if cached.Metadata.TokenSource == confidential.TokenSourceCache {
		fmt.Println("  PASS  the second call was served from the ordinary Bearer cache entry.")
	} else {
		fmt.Println("  NOTE  the second call was not served from cache (the token may have been near expiry).")
	}

	fmt.Println()
	fmt.Println("  The certificate authenticated the TLS connection to the mtlsauth.* endpoint,")
	fmt.Println("  but the token it returned is an ordinary Bearer token: it can be presented to")
	fmt.Println("  the resource over a plain connection, with no certificate involved.")
	return nil
}

// showCredentialGuardrail demonstrates the one way WithSendCertificateOverMtls can fail fast:
// confidential.New rejects it for any credential that is not a certificate, because there would be
// nothing to present on the handshake. It runs entirely offline -- confidential.New performs no
// network I/O -- so this section prints even without a certificate or connectivity.
func showCredentialGuardrail(cfg config) error {
	section("guardrail: the option requires a certificate credential (offline)")
	// Not a secret: this literal exists only to be rejected, and is never sent anywhere.
	secretCred, err := confidential.NewCredFromSecret("placeholder-value-that-is-not-a-secret")
	if err != nil {
		return fmt.Errorf("NewCredFromSecret failed: %w", err)
	}
	_, err = confidential.New(cfg.authority, cfg.clientID, secretCred, confidential.WithSendCertificateOverMtls())
	if err == nil {
		return fmt.Errorf("confidential.New accepted a secret credential with WithSendCertificateOverMtls; it must reject it")
	}
	kv("New(secret credential)", "rejected")
	kv("error", err.Error())
	fmt.Println("  PASS  only a NewCredFromCert credential can be sent over mTLS.")
	return nil
}

// buildClient constructs the confidential client, applying the regional mtlsauth endpoint when a
// region is configured. extra carries the feature under demonstration.
func buildClient(cfg config, cred confidential.Credential, extra ...confidential.Option) (confidential.Client, error) {
	opts := extra
	if cfg.region != "" {
		opts = append(opts, confidential.WithAzureRegion(cfg.region))
	}
	return confidential.New(cfg.authority, cfg.clientID, cred, opts...)
}

// loadCertificate reads a PEM file holding a certificate and its private key and builds a
// NewCredFromCert credential from it, the same way apps/tests/integration's getCertDataFromFile
// does. It also returns the parsed leaf so the caller can print its x5t#S256 thumbprint. No
// certificate, key or secret is ever embedded in this program or written to its output.
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

// cnfThumbprintFromToken decodes an access token's JWT body and returns its cnf["x5t#S256"] claim --
// the thumbprint of the certificate the token is bound to -- using the approach that
// apps/tests/integration/mtls_pop_integration_test.go's checkTokenBoundToCertificate takes. ok is
// false when the token is not a JWT this program can decode, which is a reason to say nothing rather
// than to fail: TokenType and BindingCertificate are the authoritative evidence and the cnf claim
// only corroborates them. An empty claim with ok true means the token is unbound.
func cnfThumbprintFromToken(token string) (thumbprint string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		Cnf map[string]string `json:"cnf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}
	return claims.Cnf["x5t#S256"], true
}

// thumbprintOfCert returns the base64url-encoded SHA-256 thumbprint (x5t#S256) of a certificate: the
// value that would appear in an mtls_pop token's cnf claim, and that is absent from this demo's
// Bearer token.
func thumbprintOfCert(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// tokenSourceName renders a TokenSource for display.
func tokenSourceName(s confidential.TokenSource) string {
	switch s {
	case confidential.TokenSourceCache:
		return "cache"
	case confidential.TokenSourceIdentityProvider:
		return "identity-provider"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// regionLabel describes the configured region for display.
func regionLabel(region string) string {
	if region == "" {
		return "<none - global mtlsauth endpoint>"
	}
	return region
}

// section prints a labelled banner so the output is easy to follow on a screen.
func section(title string) {
	fmt.Println()
	fmt.Println("== " + title + " ==")
}

// kv prints an aligned "key: value" line.
func kv(key, value string) {
	fmt.Printf("  %-32s %s\n", key+":", value)
}

// env returns the environment variable's value when it is set to something non-blank, else def.
func env(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}
