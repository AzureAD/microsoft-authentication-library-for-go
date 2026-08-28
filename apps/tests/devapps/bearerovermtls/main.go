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
// show the token is cached under the ordinary Bearer-token key.
//
// Usage:
//
//	go run ./apps/tests/devapps/bearerovermtls -cert /path/to/sni-cert.pem
//
// See README.md in this directory for flags, environment variables and expected output.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/tests/devapps/internal/mtlsdemo"
)

// Helpers shared by the demos in this PR live in apps/tests/devapps/internal/mtlsdemo. A small
// overlap with sibling-PR demos such as mtlspop is left in place on purpose so each PR in the
// mTLS stack stays runnable on its own branch.

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
	fs.StringVar(&cfg.clientID, "client-id", mtlsdemo.Env("MTLS_CLIENT_ID", mtlsdemo.DefaultClientID), "application (client) ID")
	fs.StringVar(&cfg.authority, "authority", mtlsdemo.Env("MTLS_AUTHORITY", mtlsdemo.DefaultAuthority), "authority URL (must be tenanted)")
	fs.StringVar(&cfg.region, "region", mtlsdemo.Env("MTLS_REGION", mtlsdemo.DefaultRegion), "Azure region for the regional mtlsauth endpoint (empty to use the global one)")
	fs.StringVar(&cfg.certPath, "cert", mtlsdemo.Env("MTLS_CERT_PATH", ""), "path to a PEM file holding the SN/I certificate and its private key")
	fs.StringVar(&cfg.scope, "scope", mtlsdemo.Env("MTLS_SCOPE", mtlsdemo.DefaultScope), "resource scope to request")
	if err := fs.Parse(args); err != nil {
		return err
	}

	mtlsdemo.Section("configuration")
	mtlsdemo.KV("authority", cfg.authority)
	mtlsdemo.KV("client id", cfg.clientID)
	mtlsdemo.KV("region", mtlsdemo.RegionLabel(cfg.region))
	mtlsdemo.KV("scope", cfg.scope)

	// This part needs neither a certificate nor the network, so it always runs and the demo prints
	// something useful even when it is invoked with no arguments at all.
	if err := showCredentialGuardrail(cfg); err != nil {
		return err
	}

	cred, leaf, err := mtlsdemo.LoadCertificate(cfg.certPath)
	if err != nil {
		return err
	}
	mtlsdemo.Section("certificate")
	mtlsdemo.KV("x5t#S256", mtlsdemo.ThumbprintOfCert(leaf))

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

	mtlsdemo.Section("acquire")
	// Note what is NOT here: no per-request option. A per-request WithMtlsProofOfPossession would
	// take precedence over the app-level flag and produce a bound mtls_pop token instead.
	result, err := app.AcquireTokenByCredential(ctx, []string{cfg.scope})
	if err != nil {
		return fmt.Errorf("AcquireTokenByCredential over mTLS failed: %w", err)
	}
	mtlsdemo.KV("Metadata.TokenType", result.Metadata.TokenType)
	mtlsdemo.KV("Metadata.TokenSource", mtlsdemo.TokenSourceName(result.Metadata.TokenSource))
	if result.BindingCertificate == nil {
		mtlsdemo.KV("AuthResult.BindingCertificate", "<nil>")
	} else {
		mtlsdemo.KV("AuthResult.BindingCertificate", "<non-nil!>")
	}
	cnf, cnfReadable := cnfThumbprintFromToken(result.AccessToken)
	switch {
	case !cnfReadable:
		mtlsdemo.KV(`token cnf["x5t#S256"]`, "<access token is not an inspectable JWT>")
	case cnf == "":
		mtlsdemo.KV(`token cnf["x5t#S256"]`, "<absent - the token is unbound>")
	default:
		mtlsdemo.KV(`token cnf["x5t#S256"]`, cnf)
	}

	// A plain Bearer token is cached under the ordinary Bearer-token key, so a second call for the
	// same scope is served from the cache rather than from Entra ID.
	mtlsdemo.Section("acquire again (same client, same scope)")
	cached, err := app.AcquireTokenByCredential(ctx, []string{cfg.scope})
	if err != nil {
		return fmt.Errorf("second AcquireTokenByCredential failed: %w", err)
	}
	mtlsdemo.KV("Metadata.TokenType", cached.Metadata.TokenType)
	mtlsdemo.KV("Metadata.TokenSource", mtlsdemo.TokenSourceName(cached.Metadata.TokenSource))
	mtlsdemo.KV("same access token as #1", fmt.Sprint(cached.AccessToken == result.AccessToken))

	mtlsdemo.Section("verification")
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
		fmt.Println("  PASS  the second call was served from the ordinary Bearer-token entry.")
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
	mtlsdemo.Section("guardrail: the option requires a certificate credential (offline)")
	// Not a secret: this literal exists only to be rejected, and is never sent anywhere.
	secretCred, err := confidential.NewCredFromSecret("placeholder-value-that-is-not-a-secret")
	if err != nil {
		return fmt.Errorf("NewCredFromSecret failed: %w", err)
	}
	_, err = confidential.New(cfg.authority, cfg.clientID, secretCred, confidential.WithSendCertificateOverMtls())
	if err == nil {
		return fmt.Errorf("confidential.New accepted a secret credential with WithSendCertificateOverMtls; it must reject it")
	}
	mtlsdemo.KV("New(secret credential)", "rejected")
	mtlsdemo.KV("error", err.Error())
	fmt.Println("  PASS  only a certificate credential can be sent over mTLS.")
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