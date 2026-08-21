// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// runBearerOverMtls demonstrates PR #643: the same certificate credential, but the client is built
// with WithSendCertificateOverMtls. The certificate is presented on the mutual-TLS handshake and the
// request is routed to the mtlsauth.* endpoint, yet the returned token is an ordinary, UNBOUND Bearer
// token: TokenType stays "Bearer" and AuthResult.BindingCertificate is nil.
func runBearerOverMtls(args []string) error {
	fs := flag.NewFlagSet("bearer-over-mtls", flag.ExitOnError)
	var cfg config
	registerCommonFlags(fs, &cfg)
	fs.StringVar(&cfg.scope, "scope", env("MTLS_POP_SCOPE", defaultPoPScope), "resource scope to request")
	if err := fs.Parse(args); err != nil {
		return err
	}

	section("Bearer over mTLS (PR #643)")
	kv("authority", cfg.authority)
	kv("client id", cfg.clientID)
	kv("scope", cfg.scope)

	cred, leaf, err := loadCertificate(cfg.certPath)
	if err != nil {
		return err
	}
	kv("certificate x5t#S256", thumbprintOfCert(leaf))

	// WithSendCertificateOverMtls is an app-level option: the certificate authenticates the transport
	// but the token is not bound to it.
	app, err := buildClient(cfg, cred, confidential.WithSendCertificateOverMtls())
	if err != nil {
		return fmt.Errorf("confidential.New failed: %w", err)
	}

	result, err := app.AcquireTokenByCredential(context.Background(), []string{cfg.scope})
	if err != nil {
		return fmt.Errorf("AcquireTokenByCredential over mTLS failed: %w", err)
	}

	section("result")
	kv("Metadata.TokenType", result.Metadata.TokenType)
	if result.BindingCertificate == nil {
		kv("AuthResult.BindingCertificate", "<nil>")
	} else {
		kv("AuthResult.BindingCertificate", "<non-nil!>")
	}
	cnf, err := cnfThumbprintFromToken(result.AccessToken)
	if err != nil {
		return fmt.Errorf("could not read the cnf claim from the token: %w", err)
	}
	if cnf == "" {
		kv("token cnf[\"x5t#S256\"]", "<absent — unbound token>")
	} else {
		kv("token cnf[\"x5t#S256\"]", cnf)
	}

	section("verification")
	if result.Metadata.TokenType != "Bearer" {
		return fmt.Errorf("expected token_type Bearer, got %q", result.Metadata.TokenType)
	}
	if result.BindingCertificate != nil {
		return fmt.Errorf("expected a nil BindingCertificate for an unbound Bearer token")
	}
	if cnf != "" {
		return fmt.Errorf("unexpected cnf claim %q on a Bearer token: it should be unbound", cnf)
	}
	fmt.Println("  OK: token_type is Bearer and BindingCertificate is nil.")
	fmt.Println("  The token is unbound, yet the request travelled over the mutual-TLS transport")
	fmt.Println("  (the certificate authenticated the connection to the mtlsauth.* endpoint).")
	return nil
}
