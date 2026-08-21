// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// buildClient constructs a confidential client from a certificate credential, applying the regional
// endpoint when a region is configured. Extra options (for example WithSendCertificateOverMtls) are
// appended by the caller.
func buildClient(cfg config, cred confidential.Credential, extra ...confidential.Option) (confidential.Client, error) {
	opts := extra
	if cfg.region != "" {
		opts = append(opts, confidential.WithAzureRegion(cfg.region))
	}
	return confidential.New(cfg.authority, cfg.clientID, cred, opts...)
}

// runMtlsPoP demonstrates PR #632: an mTLS proof-of-possession token. It acquires a token with
// WithMtlsProofOfPossession, then shows that the token_type is mtls_pop and that the certificate MSAL
// returned (BindingCertificateThumbprint) is the same one named in the token's cnf["x5t#S256"] claim.
func runMtlsPoP(args []string) error {
	fs := flag.NewFlagSet("mtls-pop", flag.ExitOnError)
	var cfg config
	registerCommonFlags(fs, &cfg)
	fs.StringVar(&cfg.scope, "scope", env("MTLS_POP_SCOPE", defaultPoPScope), "resource scope to request")
	if err := fs.Parse(args); err != nil {
		return err
	}

	section("mTLS proof-of-possession (PR #632)")
	kv("authority", cfg.authority)
	kv("client id", cfg.clientID)
	kv("scope", cfg.scope)

	cred, leaf, err := loadCertificate(cfg.certPath)
	if err != nil {
		return err
	}
	kv("certificate x5t#S256", thumbprintOfCert(leaf))

	app, err := buildClient(cfg, cred)
	if err != nil {
		return fmt.Errorf("confidential.New failed: %w", err)
	}

	result, err := app.AcquireTokenByCredential(context.Background(), []string{cfg.scope},
		confidential.WithMtlsProofOfPossession())
	if err != nil {
		return fmt.Errorf("AcquireTokenByCredential with mTLS PoP failed: %w", err)
	}

	section("result")
	kv("Metadata.TokenType", result.Metadata.TokenType)
	kv("BindingCertificateThumbprint()", result.BindingCertificateThumbprint())

	cnf, err := cnfThumbprintFromToken(result.AccessToken)
	if err != nil {
		return fmt.Errorf("could not read the cnf claim from the token: %w", err)
	}
	if cnf == "" {
		return fmt.Errorf("the token carries no cnf[\"x5t#S256\"] claim, so it is not certificate-bound")
	}
	kv("token cnf[\"x5t#S256\"]", cnf)

	section("verification")
	if result.Metadata.TokenType != "mtls_pop" {
		return fmt.Errorf("expected token_type mtls_pop, got %q", result.Metadata.TokenType)
	}
	if result.BindingCertificateThumbprint() != cnf {
		return fmt.Errorf("thumbprint mismatch: result %q vs token cnf %q",
			result.BindingCertificateThumbprint(), cnf)
	}
	fmt.Println("  OK: token_type is mtls_pop and the binding thumbprint matches the token's cnf claim.")
	fmt.Println("  The token is cryptographically bound to the certificate presented on the TLS handshake.")
	return nil
}
