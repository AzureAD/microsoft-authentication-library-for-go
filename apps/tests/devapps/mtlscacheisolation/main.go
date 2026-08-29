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
// binding certificate's x5t#S256 thumbprint; the Bearer token's key ID is empty. So the two tokens
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
	"fmt"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/tests/devapps/internal/mtlsdemo"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "\nerror: %s\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := mtlsdemo.ParseFlags("mtlscacheisolation", "authority URL (must be tenanted for mTLS PoP)", args)
	if err != nil {
		return err
	}
	mtlsdemo.PrintConfig(cfg)

	cred, leaf, err := mtlsdemo.LoadCertificate(cfg.CertPath)
	if err != nil {
		return err
	}
	mtlsdemo.KV("certificate x5t#S256", mtlsdemo.ThumbprintOfCert(leaf))

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
	if cfg.Region != "" {
		opts = append(opts, confidential.WithAzureRegion(cfg.Region))
	}
	app, err := confidential.New(cfg.Authority, cfg.ClientID, cred, opts...)
	if err != nil {
		return fmt.Errorf("confidential.New failed: %w", err)
	}

	ctx := context.Background()
	scopes := []string{cfg.Scope}

	acquirePoP := func() (confidential.AuthResult, error) {
		return app.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
	}
	acquireBearer := func() (confidential.AuthResult, error) {
		return app.AcquireTokenByCredential(ctx, scopes)
	}

	mtlsdemo.Section("interleaved acquisitions (same client, same scope, same certificate)")

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

	mtlsdemo.Section("verification")

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
		return fmt.Errorf("the PoP and Bearer acquisition returned the same access token; the cache entries collided")
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
	fmt.Println("        the Bearer token is not. Serving one for the other would silently change")
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
	mtlsdemo.KV(label+" token_type", res.Metadata.TokenType)
	mtlsdemo.KV(label+" source", mtlsdemo.TokenSourceName(res.Metadata.TokenSource))
	mtlsdemo.KV(label+" BindingCertificate", binding)
	mtlsdemo.KV(label+" token fingerprint", tokenFingerprint(res.AccessToken))
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
