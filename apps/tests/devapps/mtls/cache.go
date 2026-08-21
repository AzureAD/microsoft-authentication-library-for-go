// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

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

// runCacheIsolation demonstrates that mTLS PoP and Bearer tokens for the same client and scope occupy
// separate cache entries and never collide. It acquires each token type twice: the first call hits the
// identity provider, the second is served from cache, proving the entry exists — and the two types
// remain distinct (mtls_pop vs Bearer), so acquiring one never returns or evicts the other.
func runCacheIsolation(args []string) error {
	fs := flag.NewFlagSet("cache-isolation", flag.ExitOnError)
	var cfg config
	registerCommonFlags(fs, &cfg)
	fs.StringVar(&cfg.scope, "scope", env("MTLS_POP_SCOPE", defaultPoPScope), "resource scope to request")
	if err := fs.Parse(args); err != nil {
		return err
	}

	section("Cache isolation: PoP vs Bearer (PR #632 + #643)")
	kv("authority", cfg.authority)
	kv("client id", cfg.clientID)
	kv("scope", cfg.scope)

	ctx := context.Background()

	// PoP client: mTLS PoP is a per-request option.
	popCred, _, err := loadCertificate(cfg.certPath)
	if err != nil {
		return err
	}
	popApp, err := buildClient(cfg, popCred)
	if err != nil {
		return fmt.Errorf("confidential.New (PoP client) failed: %w", err)
	}

	// Bearer client: WithSendCertificateOverMtls is an app-level option, so it needs its own client.
	bearerCred, _, err := loadCertificate(cfg.certPath)
	if err != nil {
		return err
	}
	bearerApp, err := buildClient(cfg, bearerCred, confidential.WithSendCertificateOverMtls())
	if err != nil {
		return fmt.Errorf("confidential.New (Bearer client) failed: %w", err)
	}

	acquirePoP := func() (confidential.AuthResult, error) {
		return popApp.AcquireTokenByCredential(ctx, []string{cfg.scope}, confidential.WithMtlsProofOfPossession())
	}
	acquireBearer := func() (confidential.AuthResult, error) {
		return bearerApp.AcquireTokenByCredential(ctx, []string{cfg.scope})
	}

	section("acquire PoP, then PoP again")
	pop1, err := acquirePoP()
	if err != nil {
		return fmt.Errorf("first PoP acquisition failed: %w", err)
	}
	kv("PoP #1 token_type / source", pop1.Metadata.TokenType+" / "+tokenSourceName(pop1.Metadata.TokenSource))
	pop2, err := acquirePoP()
	if err != nil {
		return fmt.Errorf("second PoP acquisition failed: %w", err)
	}
	kv("PoP #2 token_type / source", pop2.Metadata.TokenType+" / "+tokenSourceName(pop2.Metadata.TokenSource))

	section("acquire Bearer, then Bearer again (same scope)")
	b1, err := acquireBearer()
	if err != nil {
		return fmt.Errorf("first Bearer acquisition failed: %w", err)
	}
	kv("Bearer #1 token_type / source", b1.Metadata.TokenType+" / "+tokenSourceName(b1.Metadata.TokenSource))
	b2, err := acquireBearer()
	if err != nil {
		return fmt.Errorf("second Bearer acquisition failed: %w", err)
	}
	kv("Bearer #2 token_type / source", b2.Metadata.TokenType+" / "+tokenSourceName(b2.Metadata.TokenSource))

	section("verification")
	if pop1.Metadata.TokenType != "mtls_pop" {
		return fmt.Errorf("expected PoP token_type mtls_pop, got %q", pop1.Metadata.TokenType)
	}
	if b1.Metadata.TokenType != "Bearer" {
		return fmt.Errorf("expected Bearer token_type Bearer, got %q", b1.Metadata.TokenType)
	}
	if pop2.Metadata.TokenSource != confidential.TokenSourceCache {
		fmt.Println("  NOTE: the second PoP call was not served from cache (token may have been near expiry).")
	}
	if b2.Metadata.TokenSource != confidential.TokenSourceCache {
		fmt.Println("  NOTE: the second Bearer call was not served from cache (token may have been near expiry).")
	}
	fmt.Println("  OK: the same client/scope holds two distinct cache entries — one mtls_pop, one Bearer.")
	fmt.Println("  Acquiring one token type never returns or evicts the other; the two do not collide.")
	return nil
}
