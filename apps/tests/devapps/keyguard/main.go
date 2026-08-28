//go:build windows

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Command keyguard demonstrates the complete MSAL Go flow for a non-exportable Windows key:
//
//	public API -> developer code -> real credential -> token acquisition
//	  -> returned binding certificate -> resource call
//
// The private key stays inside CNG for the whole run. It is never exported, never converted to an
// *rsa.PrivateKey, and it is used only to sign the TLS handshakes that MSAL performs against Entra
// and that this program performs against the protected resource.
//
// Run it against a certificate whose key is KeyGuard (VBS) protected:
//
//	go run ./apps/tests/devapps/keyguard \
//	  -thumbprint 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF \
//	  -client-id  <app registration client id> \
//	  -authority  https://login.microsoftonline.com/<tenant id>
//
// See README.md in this directory for how to provision such a key and what the app registration
// needs.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/tests/devapps/keyguard/ncryptsigner"
)

const (
	defaultStoreLocation = "CurrentUser"
	defaultStoreName     = "My"

	// defaultScope and defaultResourceURL point at the Microsoft Graph mTLS host. The regular
	// graph.microsoft.com host does not perform a client-certificate handshake, so a bound token has
	// to be presented to the dedicated mTLS host for the proof-of-possession to mean anything.
	defaultScope       = "https://graph.microsoft.com/.default"
	defaultResourceURL = "https://mtlstb.graph.microsoft.com/v1.0/applications?$top=1"
)

type config struct {
	thumbprint    string
	storeLocation string
	storeName     string
	clientID      string
	authority     string
	scope         string
	resourceURL   string
}

// envOr lets every flag be supplied either on the command line or through the environment, which is
// what makes the same program usable interactively and from a pipeline.
func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func parseConfig() (config, error) {
	var c config
	flag.StringVar(&c.thumbprint, "thumbprint", os.Getenv("KEYGUARD_THUMBPRINT"),
		"SHA-256 thumbprint of the certificate to use (env KEYGUARD_THUMBPRINT)")
	flag.StringVar(&c.storeLocation, "store-location", envOr("KEYGUARD_STORE_LOCATION", defaultStoreLocation),
		"certificate store location: CurrentUser or LocalMachine (env KEYGUARD_STORE_LOCATION)")
	flag.StringVar(&c.storeName, "store-name", envOr("KEYGUARD_STORE_NAME", defaultStoreName),
		"certificate store name (env KEYGUARD_STORE_NAME)")
	flag.StringVar(&c.clientID, "client-id", os.Getenv("KEYGUARD_CLIENT_ID"),
		"client ID of the app registration the certificate is registered on (env KEYGUARD_CLIENT_ID)")
	flag.StringVar(&c.authority, "authority", os.Getenv("KEYGUARD_AUTHORITY"),
		"tenanted authority, e.g. https://login.microsoftonline.com/<tenant id> (env KEYGUARD_AUTHORITY)")
	flag.StringVar(&c.scope, "scope", envOr("KEYGUARD_SCOPE", defaultScope),
		"scope to request (env KEYGUARD_SCOPE)")
	flag.StringVar(&c.resourceURL, "resource", envOr("KEYGUARD_RESOURCE_URL", defaultResourceURL),
		"protected resource to call over mTLS with the bound token; empty skips the call (env KEYGUARD_RESOURCE_URL)")
	flag.Parse()

	// Missing configuration is a normal condition for a sample, so report it as a plain actionable
	// error rather than letting a later call panic on an empty string.
	var missing []string
	if c.thumbprint == "" {
		missing = append(missing, "-thumbprint (or KEYGUARD_THUMBPRINT)")
	}
	if c.clientID == "" {
		missing = append(missing, "-client-id (or KEYGUARD_CLIENT_ID)")
	}
	if c.authority == "" {
		missing = append(missing, "-authority (or KEYGUARD_AUTHORITY)")
	}
	if len(missing) > 0 {
		return c, fmt.Errorf("missing required configuration: %s\nrun with -h for the full list of options",
			strings.Join(missing, ", "))
	}
	// Checked here so the run stops before a token is ever minted for a resource that can't
	// receive it safely.
	if c.resourceURL != "" {
		if err := requireHTTPS(c.resourceURL); err != nil {
			return c, err
		}
	}
	return c, nil
}

// requireHTTPS rejects a resource URL that isn't https.
//
// Proof-of-possession binds the token to a certificate, but the token is still a credential: over
// http:// the Authorization header would cross the network in cleartext, and the mTLS handshake that
// proves possession of the key would not happen at all, so the binding would buy nothing.
func requireHTTPS(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("resource URL %q isn't a valid URL: %w", rawURL, err)
	}
	if u.Scheme == "" {
		return fmt.Errorf("resource URL %q has no scheme; it must be an absolute https:// URL", rawURL)
	}
	// url.Parse already lower-cases the scheme (RFC 3986 treats it as case-insensitive), so an
	// exact comparison here still accepts HTTPS:// and mixed-case spellings.
	if u.Scheme != "https" {
		return fmt.Errorf("resource URL %q uses the %q scheme; this sample sends the bound token only "+
			"over https, because any other scheme would put the Authorization header on the network in "+
			"cleartext and skip the mTLS handshake that proves possession of the key", rawURL, u.Scheme)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nkeyguard sample failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := parseConfig()
	if err != nil {
		return err
	}

	// Step 1: open the certificate and bind to its CNG key. The Signer is a crypto.Signer; the
	// private key is never materialized in this process.
	signer, err := ncryptsigner.Open(cfg.storeLocation, cfg.storeName, cfg.thumbprint)
	if err != nil {
		return fmt.Errorf("opening the certificate failed: %w", err)
	}
	defer signer.Close()

	fmt.Println("== certificate ==")
	fmt.Printf("store       : %s\\%s\n", cfg.storeLocation, cfg.storeName)
	fmt.Printf("subject     : %s\n", signer.Certificate().Subject)
	fmt.Printf("issuer      : %s\n", signer.Certificate().Issuer)
	fmt.Printf("not after   : %s\n", signer.Certificate().NotAfter.Format(time.RFC3339))

	// Step 2: report whether the key really is VBS-isolated.
	//
	// The application has to make this check itself. MSAL sets its internal signer-only flag purely
	// from the Go type of the key, so it cannot distinguish a VBS-isolated key from a software key
	// wrapped in a crypto.Signer, and it deliberately makes no isolation claim. That means a
	// provisioning step that silently fell back to a software key would be completely invisible from
	// Go unless the application asks CNG directly, as this does.
	isolated, err := signer.IsVirtualIsolated()
	if err != nil {
		return fmt.Errorf("querying the CNG isolation property failed: %w", err)
	}
	fmt.Printf("VBS isolated: %t", isolated)
	if !isolated {
		fmt.Print("   <-- WARNING: this key is NOT KeyGuard protected; it is a software key")
	}
	fmt.Println()

	// Step 3: report the chain. tls.Certificate and the JWT x5c header both want the DER chain leaf
	// first. A chain of one means intermediates are missing, which some relying parties reject.
	if err := printChain(signer); err != nil {
		return err
	}

	// Step 4: build the credential from the public MSAL API. This is the entire integration surface:
	// MSAL takes a tls.Certificate whose PrivateKey is any crypto.Signer, so it needs no
	// Windows-specific code and no new API for KeyGuard.
	cred, err := confidential.NewCredFromTLSCertificate(tls.Certificate{
		Certificate: signer.Chain(),
		PrivateKey:  signer,
	})
	if err != nil {
		return fmt.Errorf("confidential.NewCredFromTLSCertificate() failed: %w", err)
	}

	app, err := confidential.New(cfg.authority, cfg.clientID, cred)
	if err != nil {
		return fmt.Errorf("confidential.New() failed: %w", err)
	}

	// Step 5: acquire the token.
	//
	// WithMtlsProofOfPossession is MANDATORY for a non-exportable key, not an optimization. It is the
	// only flow that never signs a client assertion: the mutual-TLS handshake both authenticates the
	// client and binds the token, so the key is only ever asked to sign the handshake. Every other
	// flow reaches the signer-only gate in Credential.JWT() and fails with
	//
	//	this credential's private key is not exportable and can only be used with
	//	WithMtlsProofOfPossession()
	//
	// because the JWT signing methods require an *rsa.PrivateKey, which a KeyGuard key can never be.
	ctx := context.Background()
	result, err := app.AcquireTokenByCredential(ctx, []string{cfg.scope},
		confidential.WithMtlsProofOfPossession())
	if err != nil {
		return fmt.Errorf("AcquireTokenByCredential() failed: %w", err)
	}

	fmt.Println("\n== token ==")
	fmt.Printf("token type  : %s\n", result.Metadata.TokenType)
	fmt.Printf("token source: %s\n", tokenSource(result.Metadata.TokenSource))
	fmt.Printf("expires on  : %s\n", result.ExpiresOn.Format(time.RFC3339))
	// The thumbprint below is the base64url SHA-256 of the binding certificate, which is exactly the
	// cnf["x5t#S256"] claim inside the access token. A resource compares the two to confirm the
	// caller holds the key the token was issued to.
	fmt.Printf("binding x5t#S256: %s\n", result.BindingCertificateThumbprint())

	if result.BindingCertificate == nil {
		return errors.New("the result carries no binding certificate, so the token is not certificate-bound")
	}

	// Step 6: use the token. The binding certificate MSAL returned is presented on the TLS handshake
	// and the token is sent with the "mtls_pop" scheme rather than "Bearer". Both halves are
	// required: the resource only accepts the token from the caller that can prove possession of the
	// key it is bound to.
	if cfg.resourceURL == "" {
		fmt.Println("\n== resource ==\nskipped (-resource is empty)")
		return nil
	}
	return callResource(ctx, cfg.resourceURL, result.AccessToken, result.BindingCertificate)
}

// tokenSource renders the enum, which is a plain int without a String method, as something readable.
func tokenSource(s confidential.TokenSource) string {
	switch s {
	case confidential.TokenSourceIdentityProvider:
		return "IdentityProvider"
	case confidential.TokenSourceCache:
		return "Cache"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

func printChain(signer *ncryptsigner.Signer) error {
	chain := signer.Chain()
	fmt.Printf("chain length: %d\n", len(chain))
	for i, der := range chain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parsing chain entry %d failed: %w", i, err)
		}
		label := "intermediate"
		if i == 0 {
			label = "leaf        "
		}
		fmt.Printf("  [%d] %s %s\n", i, label, cert.Subject)
	}
	if err := signer.ChainError(); err != nil {
		fmt.Printf("  WARNING: %s\n", err)
	}
	return nil
}

func callResource(ctx context.Context, resourceURL, token string, bindingCert *tls.Certificate) error {
	// Re-checked here, not just in parseConfig: this function is the unit a reader lifts into their
	// own program, and it is what actually puts the token on the network.
	if err := requireHTTPS(resourceURL); err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// The binding certificate is used exactly as MSAL returned it. Its PrivateKey is
				// still the CNG signer, so this handshake is also signed inside the VBS boundary.
				Certificates: []tls.Certificate{*bindingCert},
				MinVersion:   tls.VersionTLS12,
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceURL, nil)
	if err != nil {
		return fmt.Errorf("building the resource request failed: %w", err)
	}
	req.Header.Set("Authorization", "mtls_pop "+token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("calling %s over mTLS failed: %w", resourceURL, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	fmt.Println("\n== resource ==")
	fmt.Printf("url         : %s\n", resourceURL)
	fmt.Printf("status      : %s\n", resp.Status)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the resource rejected the bound token (HTTP %d). A 401 or 403 usually means "+
			"the binding certificate was not presented on the handshake, the app is not allow-listed for "+
			"mTLS proof-of-possession, or the Authorization scheme was not \"mtls_pop\". Response: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}
	fmt.Println("the resource accepted the certificate-bound token")
	return nil
}
