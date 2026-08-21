// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// runFIC demonstrates PR #633: leg 2 of a developer-orchestrated two-leg federated identity credential
// (FIC) flow over mTLS PoP, via NewCredFromSignedAssertionCallback returning a SignedAssertion carrying
// both the assertion and its binding certificate.
//
// Leg 2 needs a SECOND, federated application (distinct client ID) that trusts leg 1's assertion. We do
// not have one, so this subcommand ALWAYS prints the full explanation of the flow, and only attempts a
// live run when the second app is configured (via -fic-client-id / MTLS_FIC_CLIENT_ID). It never fakes
// a token: absent the config it exits 0 after explaining.
func runFIC(args []string) error {
	fs := flag.NewFlagSet("fic", flag.ExitOnError)
	var cfg config
	registerCommonFlags(fs, &cfg)
	var ficClientID, ficAuthority, exchangeScope, finalScope string
	fs.StringVar(&ficClientID, "fic-client-id", env("MTLS_FIC_CLIENT_ID", ""), "client ID of the SECOND (federated) app for leg 2 — required to run live")
	fs.StringVar(&ficAuthority, "fic-authority", env("MTLS_FIC_AUTHORITY", ""), "authority for the second app (defaults to -authority)")
	fs.StringVar(&exchangeScope, "exchange-scope", env("MTLS_EXCHANGE_SCOPE", tokenExchangeScope), "leg 1 exchange audience")
	fs.StringVar(&finalScope, "scope", env("MTLS_POP_SCOPE", defaultPoPScope), "final resource scope for leg 2")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if ficAuthority == "" {
		ficAuthority = cfg.authority
	}

	section("Two-leg FIC over mTLS PoP (PR #633)")
	fmt.Println("  The application orchestrates two mTLS proof-of-possession calls:")
	fmt.Println()
	fmt.Println("    Leg 1  SN/I certificate  ->  a certificate-bound FEDERATED ASSERTION")
	fmt.Println("           (WithMtlsProofOfPossession against the token-exchange audience;")
	fmt.Printf("            here: %s)\n", exchangeScope)
	fmt.Println()
	fmt.Println("    Leg 2  that assertion (sent as a jwt-pop client assertion) + the SAME binding")
	fmt.Println("           certificate  ->  the final mtls_pop token for the resource.")
	fmt.Println()
	fmt.Println("  Leg 2 uses NewCredFromSignedAssertionCallback, whose callback returns ONE")
	fmt.Println("  confidential.SignedAssertion{Assertion, BindingCertificate}. Returning both from a")
	fmt.Println("  single callback keeps them paired: a certificate rotation between the legs can never")
	fmt.Println("  pair one leg's assertion with another leg's certificate. This is the only API that")
	fmt.Println("  supplies leg 2's binding certificate — there is deliberately no call-site option.")

	if ficClientID == "" {
		section("live run skipped")
		fmt.Println("  No second (federated) app configured, so this demo cannot run the exchange without")
		fmt.Println("  fabricating a token — which it will not do.")
		fmt.Println()
		fmt.Println("  To run it live, supply a federated app that trusts leg 1's assertion:")
		fmt.Println("    -fic-client-id <client-id>   (or MTLS_FIC_CLIENT_ID)")
		fmt.Println("    -cert <path-to-pem>          (or MTLS_CERT_PATH) for the SN/I certificate")
		fmt.Println("  Optionally -fic-authority, -exchange-scope, -scope.")
		return nil
	}

	// Live path: both apps are configured.
	if cfg.certPath == "" {
		return fmt.Errorf("a live FIC run needs the SN/I certificate: pass -cert or set MTLS_CERT_PATH")
	}
	section("live run")
	kv("leg 1 authority", cfg.authority)
	kv("leg 1 client id", cfg.clientID)
	kv("exchange scope", exchangeScope)
	kv("leg 2 authority", ficAuthority)
	kv("leg 2 client id", ficClientID)
	kv("final scope", finalScope)

	ctx := context.Background()

	// Leg 1: SN/I cert -> cert-bound federated assertion (itself an mTLS PoP request).
	leg1Cred, _, err := loadCertificate(cfg.certPath)
	if err != nil {
		return err
	}
	leg1App, err := buildClient(cfg, leg1Cred)
	if err != nil {
		return fmt.Errorf("leg 1 confidential.New failed: %w", err)
	}
	leg1, err := leg1App.AcquireTokenByCredential(ctx, []string{exchangeScope},
		confidential.WithMtlsProofOfPossession())
	if err != nil {
		return fmt.Errorf("leg 1 AcquireTokenByCredential with mTLS PoP failed: %w", err)
	}
	kv("leg 1 token_type", leg1.Metadata.TokenType)
	if leg1.Metadata.TokenType != "mtls_pop" {
		return fmt.Errorf("leg 1 token_type = %q, want mtls_pop", leg1.Metadata.TokenType)
	}
	if leg1.BindingCertificate == nil {
		return fmt.Errorf("leg 1 returned no binding certificate")
	}

	// Leg 2: federated assertion (jwt-pop) + the SAME binding certificate -> final mtls_pop token.
	leg2Cred := confidential.NewCredFromSignedAssertionCallback(
		func(context.Context, confidential.AssertionRequestOptions) (confidential.SignedAssertion, error) {
			return confidential.SignedAssertion{
				Assertion:          leg1.AccessToken,
				BindingCertificate: leg1.BindingCertificate,
			}, nil
		})
	leg2App, err := confidential.New(ficAuthority, ficClientID, leg2Cred)
	if err != nil {
		return fmt.Errorf("leg 2 confidential.New failed: %w", err)
	}
	final, err := leg2App.AcquireTokenByCredential(ctx, []string{finalScope},
		confidential.WithMtlsProofOfPossession())
	if err != nil {
		return fmt.Errorf("leg 2 AcquireTokenByCredential with mTLS PoP failed: %w", err)
	}

	section("result")
	kv("final token_type", final.Metadata.TokenType)
	kv("final BindingCertificateThumbprint()", final.BindingCertificateThumbprint())
	if final.Metadata.TokenType != "mtls_pop" {
		return fmt.Errorf("final token_type = %q, want mtls_pop", final.Metadata.TokenType)
	}
	fmt.Println("  OK: both legs produced mtls_pop tokens; leg 2 was bound to leg 1's certificate.")
	return nil
}
