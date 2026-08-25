// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Command mtlscacheisolation demonstrates that mTLS proof-of-possession tokens and Bearer tokens do
// not collide in MSAL's token cache, even when they are acquired by the same client, for the same
// scope, with the same certificate.
//
// It needs both features in the mTLS stack, which is why it lives here:
//
//	confidential.WithMtlsProofOfPossession()   per-request  -> token_type=mtls_pop, bound to the cert
//	confidential.WithSendCertificateOverMtls() app-level    -> token_type=Bearer,   bound to nothing
//
// MSAL keys an access-token cache entry on the token type together with the authentication scheme's
// key ID (see AuthnSchemeKeyID in apps/internal/base/storage). The mtls_pop scheme's key ID is the
// binding certificate's x5t#S256 thumbprint; the Bearer scheme's key ID is empty. So the two tokens
// land in two separate entries and neither can be returned in place of, or evict, the other.
//
// The demo acquires the two types INTERLEAVED -- PoP, Bearer, PoP, Bearer -- because that ordering
// is what actually proves isolation. If the two shared a cache entry, acquiring the Bearer token in
// between would have overwritten the PoP entry and the second PoP call would have gone back to Entra
// ID (or, worse, returned the Bearer token). Both second calls being served from cache, each with
// its own token type and its own token value, is the result that can only happen if the entries are
// distinct.
//
// Usage:
//
//	go run ./apps/tests/devapps/mtlscacheisolation -cert /path/to/sni-cert.pem
//
// See README.md in this directory for flags, environment variables and expected output.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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
	fs := flag.NewFlagSet("mtlscacheisolation", flag.ExitOnError)
	var cfg config
	fs.StringVar(&cfg.clientID, "client-id", env("MTLS_CLIENT_ID", defaultClientID), "application (client) ID")
	fs.StringVar(&cfg.authority, "authority", env("MTLS_AUTHORITY", defaultAuthority), "authority URL (must be tenanted for mTLS PoP)")
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

	cred, leaf, err := loadCertificate(cfg.certPath)
	if err != nil {
		return err
	}
	kv("certificate x5t#S256", thumbprintOfCert(leaf))

	// ONE client, and therefore ONE cache. That is essential to the demonstration: two clients would
	// each get their own in-memory cache, so showing that their tokens don't collide would prove
	// nothing at all.
	//
	// A single client can still produce both token types because the two options sit at different
	// levels. WithSendCertificateOverMtls is app-level and makes the default acquisition a
	// Bearer-over-mTLS one; a per-request WithMtlsProofOfPossession always takes precedence over it
	// and produces a bound mtls_pop token instead. Both requests go to the same mtlsauth.* endpoint
	// over the same certificate.
	opts := []confidential.Option{confidential.WithSendCertificateOverMtls()}
	if cfg.region != "" {
		opts = append(opts, confidential.WithAzureRegion(cfg.region))
	}
	app, err := confidential.New(cfg.authority, cfg.clientID, cred, opts...)
	if err != nil {
		return fmt.Errorf("confidential.New failed: %w", err)
	}

	ctx := context.Background()
	scopes := []string{cfg.scope}

	acquirePoP := func() (confidential.AuthResult, error) {
		return app.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
	}
	acquireBearer := func() (confidential.AuthResult, error) {
		return app.AcquireTokenByCredential(ctx, scopes)
	}

	section("interleaved acquisitions (same client, same scope, same certificate)")

	pop1, err := acquirePoP()
	if err != nil {
		return fmt.Errorf("first PoP acquisition failed: %w", err)
	}
	report("PoP #1", pop1)

	// Acquiring the Bearer token here is the load-bearing step: it is the call that would have
	// clobbered the PoP entry if the two shared a cache key.
	bearer1, err := acquireBearer()
	if err != nil {
		return fmt.Errorf("first Bearer acquisition failed: %w", err)
	}
	report("Bearer #1", bearer1)

	pop2, err := acquirePoP()
	if err != nil {
		return fmt.Errorf("second PoP acquisition failed: %w", err)
	}
	report("PoP #2", pop2)

	bearer2, err := acquireBearer()
	if err != nil {
		return fmt.Errorf("second Bearer acquisition failed: %w", err)
	}
	report("Bearer #2", bearer2)

	section("verification")

	// 1. The two acquisitions produced genuinely different token types.
	if pop1.Metadata.TokenType != "mtls_pop" {
		return fmt.Errorf("expected PoP token_type mtls_pop, got %q", pop1.Metadata.TokenType)
	}
	if bearer1.Metadata.TokenType != "Bearer" {
		return fmt.Errorf("expected Bearer token_type Bearer, got %q", bearer1.Metadata.TokenType)
	}
	fmt.Println(`  PASS  the same client produced both an "mtls_pop" and a "Bearer" token.`)

	// 2. They are not the same token, so neither call returned the other's cache entry.
	if pop1.AccessToken == bearer1.AccessToken {
		return fmt.Errorf("the PoP and Bearer acquisitions returned the same access token; the cache entries collided")
	}
	fmt.Println("  PASS  the two access tokens are different values - no entry was shared.")

	// 3. Each repeat call came back from its own entry, unchanged, despite the other type having
	//    been acquired in between.
	if pop2.Metadata.TokenType != "mtls_pop" {
		return fmt.Errorf("PoP #2 returned token_type %q; the Bearer acquisition contaminated the PoP entry", pop2.Metadata.TokenType)
	}
	if bearer2.Metadata.TokenType != "Bearer" {
		return fmt.Errorf("Bearer #2 returned token_type %q; the PoP acquisition contaminated the Bearer entry", bearer2.Metadata.TokenType)
	}
	if pop2.AccessToken != pop1.AccessToken {
		return fmt.Errorf("PoP #2 returned a different token than PoP #1; the PoP entry did not survive the interleaved Bearer acquisition")
	}
	if bearer2.AccessToken != bearer1.AccessToken {
		return fmt.Errorf("Bearer #2 returned a different token than Bearer #1; the Bearer entry did not survive the interleaved PoP acquisition")
	}
	fmt.Println("  PASS  each repeat call returned its OWN earlier token, with its own token type,")
	fmt.Println("        even though the other type was acquired in between.")

	// 4. Cache service is the expected mechanism, but it is reported rather than required: a token
	//    close to expiry is legitimately refreshed from Entra ID, and failing the demo for that
	//    would be reporting a cache miss as a correctness bug.
	reportSource("PoP #2", pop2)
	reportSource("Bearer #2", bearer2)

	// 5. Only the PoP result is certificate-bound. This is the difference the separate cache entries
	//    exist to preserve.
	if pop1.BindingCertificate == nil {
		return fmt.Errorf("expected the mtls_pop result to carry a BindingCertificate")
	}
	if bearer1.BindingCertificate != nil {
		return fmt.Errorf("expected the Bearer result to carry no BindingCertificate")
	}
	fmt.Println("  PASS  only the mtls_pop result is certificate-bound (BindingCertificate non-nil);")
	fmt.Println("        the Bearer result is not. Serving one for the other would silently change")
	fmt.Println("        an application's security posture, which is why the entries are separate.")

	fmt.Println()
	fmt.Println("  MSAL keys an access-token cache entry on the token type plus the authentication")
	fmt.Println("  scheme's key ID. For mtls_pop that key ID is the certificate's x5t#S256 thumbprint;")
	fmt.Println("  for Bearer it is empty. Two keys, two entries, no collision.")
	return nil
}

// report prints one acquisition's outcome.
func report(label string, res confidential.AuthResult) {
	binding := "<nil>"
	if res.BindingCertificate != nil {
		binding = "bound to " + res.BindingCertificateThumbprint()
	}
	kv(label+" token_type", res.Metadata.TokenType)
	kv(label+" source", tokenSourceName(res.Metadata.TokenSource))
	kv(label+" BindingCertificate", binding)
	kv(label+" token fingerprint", tokenFingerprint(res.AccessToken))
}

// reportSource states whether a repeat call was served from cache. A miss is reported, not failed:
// MSAL legitimately refreshes a token that is close to expiry.
func reportSource(label string, res confidential.AuthResult) {
	if res.Metadata.TokenSource == confidential.TokenSourceCache {
		fmt.Printf("  PASS  %s was served from cache.\n", label)
		return
	}
	fmt.Printf("  NOTE  %s was not served from cache (the token may have been near expiry).\n", label)
}

// tokenFingerprint renders a short, non-reversible excerpt of an access token so two tokens can be
// told apart on screen. The full token is never printed: it is a live credential.
func tokenFingerprint(token string) string {
	if len(token) < 16 {
		return "<token too short to fingerprint>"
	}
	return token[:8] + "..." + token[len(token)-8:]
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

// thumbprintOfCert returns the base64url-encoded SHA-256 thumbprint (x5t#S256) of a certificate: the
// value MSAL uses as the mtls_pop cache entry's authentication-scheme key ID, and the value that
// appears in an mtls_pop token's cnf claim.
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
