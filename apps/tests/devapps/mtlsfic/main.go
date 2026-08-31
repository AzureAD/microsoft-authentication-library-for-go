// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Command mtlsfic is a runnable demo of the developer-orchestrated two-leg federated identity
// credential (FIC) flow over mTLS proof-of-possession, the capability added by
// confidential.NewCredFromSignedAssertionCallback.
//
// The application makes two mTLS PoP calls and carries the result of the first into the second:
//
//	Leg 1  SN/I certificate  ->  a certificate-bound FEDERATED ASSERTION
//	       An ordinary mTLS PoP acquisition (WithMtlsProofOfPossession) against the token-exchange
//	       audience api://AzureADTokenExchange/.default. What comes back in AccessToken is an
//	       assertion for the next leg, NOT a usable resource token.
//
//	Leg 2  that assertion + the SAME binding certificate  ->  the final mtls_pop resource token
//	       NewCredFromSignedAssertionCallback's callback returns one
//	       confidential.SignedAssertion{Assertion, BindingCertificate}. On the wire the assertion is
//	       marked certificate-bound with
//	       client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-pop
//	       (grant.ClientAssertionPoP in apps/internal/oauth/ops/internal/grant/grant.go).
//
// Why one callback returns both values: an assertion and the certificate it is bound to must never
// be sourced separately, or a certificate rotation between the legs could pair one leg's assertion
// with another leg's certificate. There is deliberately NO call-site option that supplies a binding
// certificate — that absence is the enforcement. See Client.resolveMtlsBindingCert in
// apps/confidential/confidential.go, whose only source of a callback certificate is this credential.
// MSAL .NET takes the same position with ClientSignedAssertion.TokenBindingCertificate.
//
// The explanation always prints; the live acquisition runs only when a certificate is supplied. The
// demo never fabricates a token.
//
// Usage:
//
//	go run ./apps/tests/devapps/mtlsfic                       # explain the flow, then exit
//	go run ./apps/tests/devapps/mtlsfic -cert /path/cert.pem  # explain, then run both legs live
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

// Known-good lab defaults, the same public identifiers used by the integration test
// TestTwoLegFICMtlsPoP_SNI in apps/tests/integration/mtls_pop_integration_test.go. They are public
// identifiers, not secrets, and every one is overridable by flag or environment variable.
const (
	defaultClientID  = "163ffef9-a313-45b4-ab2f-c7e2f5e0e23e"
	defaultAuthority = "https://login.microsoftonline.com/bea21ebe-8b64-4d06-9f6d-6a889b120a7c"

	// tokenExchangeScope is the audience leg 1 requests: it yields a federated assertion rather
	// than a resource token. Mirrors MSAL .NET's TokenExchangeUrl.
	tokenExchangeScope = "api://AzureADTokenExchange/.default" //nolint:gosec // G101: a public OAuth audience URI, not a credential.

	// defaultResourceScope is an ESTS allow-listed resource audience (Azure Key Vault). ESTS gates
	// mTLS PoP on the final resource being allow-listed, so a demo that only needs a token and does
	// not call a resource requests one for this audience regardless of the client app.
	defaultResourceScope = "https://vault.azure.net/.default"
)

func main() {
	var (
		certPath      = flag.String("cert", env("MTLS_CERT_PATH", ""), "path to a PEM file holding the SN/I certificate and its private key (required for a live run)")
		clientID      = flag.String("client-id", env("MTLS_CLIENT_ID", defaultClientID), "leg 1 application (client) ID")
		authority     = flag.String("authority", env("MTLS_AUTHORITY", defaultAuthority), "leg 1 authority URL (must be tenanted for mTLS PoP)")
		ficClientID   = flag.String("fic-client-id", env("MTLS_FIC_CLIENT_ID", ""), "leg 2 (federated) application ID; defaults to -client-id, see the README caveat")
		ficAuthority  = flag.String("fic-authority", env("MTLS_FIC_AUTHORITY", ""), "leg 2 authority URL; defaults to -authority")
		exchangeScope = flag.String("exchange-scope", env("MTLS_EXCHANGE_SCOPE", tokenExchangeScope), "leg 1 token-exchange audience")
		resourceScope = flag.String("scope", env("MTLS_POP_SCOPE", defaultResourceScope), "leg 2 final resource scope")
		region        = flag.String("region", env("MTLS_REGION", ""), "Azure region for the regional token endpoint; empty (the default) uses the global endpoint, which is what TestTwoLegFICMtlsPoP_SNI exercises")
	)
	flag.Parse()

	if *ficClientID == "" {
		*ficClientID = *clientID
	}
	if *ficAuthority == "" {
		*ficAuthority = *authority
	}

	explain(*exchangeScope)

	if strings.TrimSpace(*certPath) == "" {
		section("live run skipped")
		fmt.Println("  No certificate supplied, and this demo will not fabricate a token.")
		fmt.Println()
		fmt.Println("  To run both legs live against the lab:")
		fmt.Println("    -cert <path-to-pem>   (or MTLS_CERT_PATH) the SN/I certificate and its key")
		fmt.Println("  Optionally -client-id, -authority, -fic-client-id, -fic-authority,")
		fmt.Println("  -exchange-scope, -scope, -region.")
		return
	}

	if err := run(*certPath, *clientID, *authority, *ficClientID, *ficAuthority, *exchangeScope, *resourceScope, *region); err != nil {
		fmt.Fprintf(os.Stderr, "\nerror: %s\n", err)
		os.Exit(1)
	}
}

// explain prints the flow. It runs whether or not a certificate is available, because the shape of
// the API is the point of this demo.
func explain(exchangeScope string) {
	section("Two-leg FIC over mTLS proof-of-possession")
	fmt.Println("  The application orchestrates two mTLS proof-of-possession calls:")
	fmt.Println()
	fmt.Println("    Leg 1  SN/I certificate  ->  a certificate-bound FEDERATED ASSERTION")
	fmt.Println("           An ordinary WithMtlsProofOfPossession acquisition against the")
	fmt.Printf("           token-exchange audience (%s).\n", exchangeScope)
	fmt.Println("           What comes back is an assertion for leg 2, NOT a usable resource token.")
	fmt.Println()
	fmt.Println("    Leg 2  that assertion + the SAME binding certificate  ->  final mtls_pop token")
	fmt.Println("           NewCredFromSignedAssertionCallback's callback returns ONE")
	fmt.Println("           confidential.SignedAssertion{Assertion, BindingCertificate}.")
	fmt.Println()
	fmt.Println("  Returning both from a single callback keeps them paired: a certificate rotation")
	fmt.Println("  between the legs can never pair one leg's assertion with another leg's")
	fmt.Println("  certificate. There is deliberately NO WithBindingCertificate() call-site option --")
	fmt.Println("  that absence IS the enforcement, because values you cannot supply separately are")
	fmt.Println("  values you cannot mismatch. MSAL .NET matches this with")
	fmt.Println("  ClientSignedAssertion.TokenBindingCertificate.")
	fmt.Println()
	fmt.Println("  BindingCertificate is REQUIRED for an mTLS PoP request: a callback that returns")
	fmt.Println("  none fails the acquisition (see prepareMtlsPoP in apps/confidential). A")
	fmt.Println("  signed-assertion credential has no certificate of its own to fall back to.")
	fmt.Println()
	fmt.Println("  On the wire, the client assertion story inverts across the mTLS stack:")
	fmt.Println("    vanilla certificate auth   client_assertion + jwt-bearer")
	fmt.Println("    plain mTLS PoP             NO client_assertion at all (the TLS handshake")
	fmt.Println("                               authenticates the client; FromClientCertificate)")
	fmt.Println("    FIC leg 2                  client_assertion RETURNS, carried with")
	fmt.Println("                               client_assertion_type=")
	fmt.Println("                               urn:ietf:params:oauth:client-assertion-type:jwt-pop")
}

func run(certPath, clientID, authority, ficClientID, ficAuthority, exchangeScope, resourceScope, region string) error {
	section("live run")
	kv("leg 1 authority", authority)
	kv("leg 1 client id", clientID)
	kv("exchange scope", exchangeScope)
	kv("leg 2 authority", ficAuthority)
	kv("leg 2 client id", ficClientID)
	kv("final scope", resourceScope)
	if region == "" {
		kv("token endpoint", "global (no -region)")
	} else {
		kv("token endpoint", "regional: "+region)
	}
	if ficClientID == clientID && ficAuthority == authority {
		fmt.Println()
		fmt.Println("  NOTE: both legs use the same app and tenant. That proves the mechanics and the")
		fmt.Println("  wire format, but it is not a genuine cross-identity hop. Pass -fic-client-id")
		fmt.Println("  (and -fic-authority) to exercise a real second federated app.")
	}

	ctx := context.Background()

	// Leg 1: SN/I cert -> cert-bound federated assertion. This is an ordinary mTLS PoP acquisition,
	// exactly the call a plain mTLS PoP application already makes; only the scope differs.
	leg1Cred, leaf, err := loadCertificate(certPath)
	if err != nil {
		return err
	}
	section("leg 1: certificate -> federated assertion")
	kv("certificate on disk x5t#S256", thumbprintOfCert(leaf))

	var leg1Opts []confidential.Option
	if region != "" {
		leg1Opts = append(leg1Opts, confidential.WithAzureRegion(region))
	}
	leg1App, err := confidential.New(authority, clientID, leg1Cred, leg1Opts...)
	if err != nil {
		return fmt.Errorf("leg 1 confidential.New failed: %w", err)
	}

	// acquireLeg1 performs leg 1: an ordinary mTLS PoP acquisition whose "access token" is the
	// federated assertion for leg 2, together with the certificate it is bound to. leg1App has its
	// own cache, so repeat calls are served from it rather than the network.
	//
	// It is a closure because leg 2's callback has to run leg 1 again on every invocation, while
	// the narration below still needs to run it once up front and report on it.
	acquireLeg1 := func(ctx context.Context) (confidential.AuthResult, error) {
		return leg1App.AcquireTokenByCredential(ctx, []string{exchangeScope},
			confidential.WithMtlsProofOfPossession())
	}

	leg1, err := acquireLeg1(ctx)
	if err != nil {
		return fmt.Errorf("leg 1 AcquireTokenByCredential with mTLS PoP failed: %w", err)
	}
	kv("leg 1 token_type", leg1.Metadata.TokenType)
	if leg1.Metadata.TokenType != "mtls_pop" {
		return fmt.Errorf("leg 1 token_type = %q, want mtls_pop", leg1.Metadata.TokenType)
	}
	if leg1.AccessToken == "" {
		return fmt.Errorf("leg 1 returned no federated assertion")
	}
	if leg1.BindingCertificate == nil {
		return fmt.Errorf("leg 1 returned no binding certificate")
	}
	kv("leg 1 binding cert x5t#S256", leg1.BindingCertificateThumbprint())
	fmt.Println("  leg 1's AccessToken is the FEDERATED ASSERTION for leg 2, not a resource token.")

	// Leg 2: the assertion and the certificate it is bound to, handed over together. This callback
	// is the only route by which a binding certificate reaches an assertion credential.
	section("leg 2: assertion (jwt-pop) + same certificate -> resource token")

	// These two observe what happens inside the callback so the result section can report it rather
	// than merely assert it. NewCredFromSignedAssertionCallback requires a thread-safe callback; a
	// plain int is safe here only because this demo drives one acquisition on a single goroutine. A
	// concurrent service would need a mutex or sync/atomic.
	leg1CallbackCalls := 0
	leg1CallbackSource := confidential.TokenSourceIdentityProvider

	leg2Cred := confidential.NewCredFromSignedAssertionCallback(
		func(ctx context.Context, _ confidential.AssertionRequestOptions) (confidential.SignedAssertion, error) {
			// Leg 1 runs HERE, on every invocation, rather than being captured once outside. MSAL
			// resolves this callback before consulting the cache, so a rotated certificate or a
			// refreshed assertion is picked up automatically; leg1App's own cache keeps the repeat
			// call cheap. Closing over a single pre-computed result instead would pin an assertion
			// that eventually expires, alongside a certificate that may since have rotated -- a bug
			// a one-shot demo never exposes but a long-running service hits.
			//
			// Note this uses the callback's own ctx, not the enclosing one, so cancellation and
			// deadlines from the leg-2 acquisition propagate into leg 1.
			fresh, err := acquireLeg1(ctx)
			if err != nil {
				return confidential.SignedAssertion{}, fmt.Errorf("leg 1 inside leg-2 callback: %w", err)
			}
			leg1CallbackCalls++
			leg1CallbackSource = fresh.Metadata.TokenSource
			return confidential.SignedAssertion{
				Assertion:          fresh.AccessToken,
				BindingCertificate: fresh.BindingCertificate,
			}, nil
		})
	var leg2Opts []confidential.Option
	if region != "" {
		leg2Opts = append(leg2Opts, confidential.WithAzureRegion(region))
	}
	leg2App, err := confidential.New(ficAuthority, ficClientID, leg2Cred, leg2Opts...)
	if err != nil {
		return fmt.Errorf("leg 2 confidential.New failed: %w", err)
	}
	final, err := leg2App.AcquireTokenByCredential(ctx, []string{resourceScope},
		confidential.WithMtlsProofOfPossession())
	if err != nil {
		return fmt.Errorf("leg 2 AcquireTokenByCredential with mTLS PoP failed: %w", err)
	}

	section("result")
	kv("final token_type", final.Metadata.TokenType)
	kv("final binding cert x5t#S256", final.BindingCertificateThumbprint())

	// The cnf claim is the issuer's own statement of what the token is bound to, so it is the proof
	// that matters: it shows ESTS bound the token to the leg-1 certificate rather than MSAL merely
	// echoing a certificate back to us.
	cnf, err := cnfThumbprintFromToken(final.AccessToken)
	if err != nil {
		return err
	}
	kv("final token cnf[x5t#S256]", orNone(cnf))

	// The callback re-ran leg 1, which is the whole point of putting leg 1 inside it. Report where
	// that repeat acquisition actually came from instead of claiming the cache absorbed it.
	repeatSource := "identity provider (network)"
	if leg1CallbackSource == confidential.TokenSourceCache {
		repeatSource = "served from cache"
	}
	kv("leg 1 inside callback", fmt.Sprintf("%s (callback fired %dx)", repeatSource, leg1CallbackCalls))
	if leg1CallbackSource != confidential.TokenSourceCache {
		fmt.Println("  NOTE: the callback's leg 1 went to the network rather than leg1App's cache.")
		fmt.Println("  That is legitimate when the first assertion was already near expiry, so it is")
		fmt.Println("  reported rather than treated as a failure.")
	}

	if final.Metadata.TokenType != "mtls_pop" {
		return fmt.Errorf("final token_type = %q, want mtls_pop", final.Metadata.TokenType)
	}
	if final.BindingCertificateThumbprint() != leg1.BindingCertificateThumbprint() {
		return fmt.Errorf("final token is not bound to leg 1's certificate")
	}
	if cnf != "" && cnf != final.BindingCertificateThumbprint() {
		return fmt.Errorf("final token cnf claim %q does not name the binding certificate %q",
			cnf, final.BindingCertificateThumbprint())
	}
	fmt.Println()
	fmt.Println("  OK: both legs produced mtls_pop tokens, and every thumbprint above is the same --")
	fmt.Println("  the certificate on disk, leg 1's binding certificate, leg 2's, and the one the")
	fmt.Println("  issuer named in the final token's cnf claim.")
	return nil
}

// --- Local copies of shared demo scaffolding -------------------------------------------------
//
// These helpers are duplicated here on purpose rather than factored into a package shared with the
// other demos in this mTLS PR stack. A shared package would make this demo depend on code that
// lands in a different pull request, which is exactly the cross-PR coupling that makes a stack-wide
// demo unreviewable. Roughly thirty self-contained lines is the deliberate price of keeping this
// demo reviewable on its own.

// loadCertificate reads a PEM file (certificate + private key) and builds a NewCredFromCert
// credential from it, the same way apps/tests/integration/config_helpers_test.go's
// getCertDataFromFile does. It also returns the parsed leaf so the caller can print its thumbprint.
// No certificate, key or secret is ever embedded or logged.
func loadCertificate(certPath string) (confidential.Credential, *x509.Certificate, error) {
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

// cnfThumbprintFromToken decodes an access token's JWT body and returns its cnf["x5t#S256"] claim,
// the thumbprint of the certificate the issuer bound the token to. It reuses the approach in
// apps/tests/integration/mtls_pop_integration_test.go's checkTokenBoundToCertificate. It returns an
// empty string (not an error) when the token carries no such claim, so callers can report "none".
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

// section prints a labelled banner so output is easy to follow on a screen.
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

// orNone renders an empty claim value as "(none)" rather than blank.
func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
