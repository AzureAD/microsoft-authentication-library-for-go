// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Command mtlspop is a runnable demonstration of mTLS proof-of-possession: an access token that is
// cryptographically bound to the certificate presented on the mutual-TLS handshake to the token
// endpoint, rather than a plain bearer token that anyone who obtains it can replay.
//
// The entire opt-in is one per-call option:
//
//	cred, _ := confidential.NewCredFromCert(certs, key)
//	app, _ := confidential.New(authority, clientID, cred) // authority must be tenanted
//	res, _ := app.AcquireTokenByCredential(ctx, scopes,
//		confidential.WithMtlsProofOfPossession())
//
// and the result carries everything needed to use the token:
//
//	res.Metadata.TokenType             == "mtls_pop"  (not "Bearer")
//	res.BindingCertificate                            the chain plus the live private key
//	res.BindingCertificateThumbprint() == the token's cnf["x5t#S256"] claim
//
// Redeeming the token takes both halves — the certificate on the connection and the token in the
// Authorization header — which the "using the token" section below shows as real code.
//
// Run with -h for flags. A certificate is required and is always supplied at runtime by path or
// environment variable; no certificate, key or token is embedded, logged or committed.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
)

// Known-good lab defaults, the same ones exercised by the integration tests in
// apps/tests/integration/mtls_pop_integration_test.go. They are public identifiers, not secrets, and
// every one is overridable by flag or environment variable.
const (
	defaultClientID  = "163ffef9-a313-45b4-ab2f-c7e2f5e0e23e"
	defaultAuthority = "https://login.microsoftonline.com/bea21ebe-8b64-4d06-9f6d-6a889b120a7c"
	defaultRegion    = "westus3"
	defaultScope     = "https://vault.azure.net/.default"

	// graphMtlsResourceURL is the Microsoft Graph mutual-TLS host, a known-good target for -resource.
	// The ordinary graph.microsoft.com host does not perform the client-certificate handshake, so an
	// mtls_pop token can only be redeemed against the dedicated mTLS host.
	graphMtlsResourceURL = "https://mtlstb.graph.microsoft.com/v1.0/applications?$top=1"
)

// config holds everything the demo reads from flags or the environment.
type config struct {
	clientID  string
	authority string
	region    string
	certPath  string
	scope     string
	resource  string
	trace     bool
}

func main() {
	var cfg config
	flag.StringVar(&cfg.clientID, "client-id", env("MTLS_CLIENT_ID", defaultClientID),
		"application (client) ID")
	flag.StringVar(&cfg.authority, "authority", env("MTLS_AUTHORITY", defaultAuthority),
		"authority URL; must be tenanted (not /common, /organizations or /consumers)")
	flag.StringVar(&cfg.region, "region", env("MTLS_REGION", defaultRegion),
		`Azure region for the regional token endpoint; pass -region "" for the global endpoint`)
	flag.StringVar(&cfg.certPath, "cert", env("MTLS_CERT_PATH", ""),
		"path to a PEM file holding the certificate and its private key (required)")
	flag.StringVar(&cfg.scope, "scope", env("MTLS_POP_SCOPE", defaultScope),
		"resource scope to request")
	flag.StringVar(&cfg.resource, "resource", env("MTLS_POP_RESOURCE", ""),
		"optional resource URL to call with the token over mTLS; empty means acquire only")
	flag.BoolVar(&cfg.trace, "trace", false,
		"print the mutual-TLS token request's URL and body parameter names (never their values)")
	flag.Parse()

	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "\nmtlspop: %s\n", errors.Verbose(err))
		os.Exit(1)
	}
}

func run(cfg config) error {
	section("mTLS proof-of-possession")
	kv("authority", cfg.authority)
	kv("client id", cfg.clientID)
	kv("scope", cfg.scope)
	if cfg.region == "" {
		kv("region", "(none: global mtlsauth endpoint)")
	} else {
		kv("region", cfg.region)
	}

	// The credential is an ordinary certificate credential. Nothing about building it is specific to
	// proof-of-possession; the same credential can mint a plain bearer token.
	cred, leaf, err := loadCertificate(cfg.certPath)
	if err != nil {
		return err
	}
	kv("certificate subject", leaf.Subject.CommonName)
	kv("certificate x5t#S256", thumbprintOfCert(leaf))

	var opts []confidential.Option
	if cfg.region != "" {
		opts = append(opts, confidential.WithAzureRegion(cfg.region))
	}
	if cfg.trace {
		// WithMtlsHTTPClient overrides how the mutual-TLS client is built. It is required whenever
		// the client passed to WithHTTPClient is not an *http.Client - notably when an application
		// reaches MSAL through Azure's azidentity. Here it is used only to observe the token
		// request; the transport it builds mirrors the one MSAL builds by default.
		opts = append(opts, confidential.WithMtlsHTTPClient(tracingMtlsClient))
	}

	// The authority must be tenanted. /common, /organizations and /consumers are rejected up front,
	// before any cache lookup or network call, because no non-tenanted authority can issue a
	// tenant-bound proof-of-possession token.
	app, err := confidential.New(cfg.authority, cfg.clientID, cred, opts...)
	if err != nil {
		return fmt.Errorf("confidential.New failed: %w", err)
	}

	// WithMtlsProofOfPossession is the whole opt-in, and it is per call: the same client still hands
	// out plain bearer tokens when it is omitted. MSAL infers the binding certificate from the
	// credential, rewrites the token endpoint from login.* to mtlsauth.*, presents the certificate as
	// the client certificate on that handshake, and asks for token_type=mtls_pop.
	//
	// Three things about this flow are easy to get wrong:
	//
	//  1. WithX5C() is inert here. mTLS PoP mints no client assertion at all, so there is no JWT
	//     header for an x5c array to ride in; the chain is presented on the TLS handshake instead.
	//     (Internally SendX5C is read in exactly one place, where a client assertion is signed, and
	//     this flow never reaches it. Passing WithX5C() is harmless but changes nothing on this call.)
	//
	//  2. The wire delta versus plain certificate authentication is a subtraction, not an addition:
	//     client_assertion and client_assertion_type are absent, and so is req_cnf. The mutual-TLS
	//     handshake both authenticates the client and binds the token. Run with -trace to see it.
	//
	//  3. mTLS PoP is app-only. It exists on AcquireTokenByCredential and nowhere else, because the
	//     binding certificate authenticates the application rather than a user.
	//
	// MSAL fails closed on a downgrade: had the identity provider answered with a plain bearer token,
	// this call would return an error rather than a token that only looks bound.
	result, err := app.AcquireTokenByCredential(context.Background(), []string{cfg.scope},
		confidential.WithMtlsProofOfPossession())
	if err != nil {
		return fmt.Errorf("AcquireTokenByCredential with mTLS PoP failed: %w", err)
	}

	section("result")
	kv("Metadata.TokenType", result.Metadata.TokenType)
	// TokenSource is an int constant with no String method, so name it rather than printing 0 or 1.
	kv("Metadata.TokenSource", label(result.Metadata.TokenSource == confidential.TokenSourceCache,
		"cache", "identity provider (network)"))
	kv("BindingCertificateThumbprint()", result.BindingCertificateThumbprint())
	kv("BindingCertificate.Leaf", label(result.BindingCertificate != nil && result.BindingCertificate.Leaf != nil,
		"present (parsed public leaf)", "absent"))
	kv("BindingCertificate.PrivateKey", label(result.BindingCertificate != nil && result.BindingCertificate.PrivateKey != nil,
		"present (live signer, for tls.Config)", "absent"))
	// The access token itself is never printed. Its cnf claim is the interesting part, and is public.
	kv("access token length", fmt.Sprintf("%d characters (not printed)", len(result.AccessToken)))

	cnf, err := cnfThumbprintFromToken(result.AccessToken)
	if err != nil {
		return fmt.Errorf("could not read the cnf claim from the token: %w", err)
	}
	if cnf == "" {
		return fmt.Errorf(`the token carries no cnf["x5t#S256"] claim, so it is not certificate-bound`)
	}
	kv(`token cnf["x5t#S256"]`, cnf)

	section("verification")
	if result.Metadata.TokenType != "mtls_pop" {
		return fmt.Errorf("expected token_type mtls_pop, got %q", result.Metadata.TokenType)
	}
	if result.BindingCertificate == nil {
		return fmt.Errorf("expected a binding certificate on the result, got nil")
	}
	if result.BindingCertificateThumbprint() != cnf {
		return fmt.Errorf("thumbprint mismatch: result %q vs token cnf %q",
			result.BindingCertificateThumbprint(), cnf)
	}
	fmt.Println("  OK: token_type is mtls_pop and the binding thumbprint matches the token's cnf claim.")
	fmt.Println("  The token is cryptographically bound to the certificate presented on the TLS handshake.")

	return useToken(cfg, result)
}

// useToken shows the half of the flow that happens after acquisition. Redeeming an mtls_pop token
// takes both halves, and neither works alone: the binding certificate goes on the connection, and
// the token goes in the Authorization header under the mtls_pop scheme rather than Bearer. A
// resource that receives the token without the matching handshake rejects it, which is the point.
//
// BindingCertificate drops straight into tls.Config.Certificates. It is deliberately not
// reassembled from the PEM file here, because MSAL handing back a directly usable certificate is
// itself the feature.
func useToken(cfg config, result confidential.AuthResult) error {
	section("using the token")

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{*result.BindingCertificate},
				MinVersion:   tls.VersionTLS12,
			},
		},
	}

	target := cfg.resource
	if target == "" {
		target = graphMtlsResourceURL
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("building the resource request failed: %w", err)
	}
	// Not "Bearer". A resource expecting proof-of-possession rejects the Bearer scheme.
	req.Header.Set("Authorization", "mtls_pop "+result.AccessToken)

	kv("tls.Config.Certificates", "[]tls.Certificate{*result.BindingCertificate}")
	kv("Authorization header", `"mtls_pop " + result.AccessToken`)
	kv("resource", target)

	if cfg.resource == "" {
		fmt.Println("  The client and request above are built but not sent; pass -resource <url> to send it.")
		fmt.Printf("  A known-good target is the Microsoft Graph mTLS host:\n    -resource %q\n", graphMtlsResourceURL)
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("mTLS resource call to %s failed: %w", target, err)
	}
	defer resp.Body.Close()

	kv("HTTP status", resp.Status)
	if resp.StatusCode != http.StatusOK {
		// Truncate the external response rather than dumping an arbitrary payload onto the screen.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("the resource did not accept the token: got HTTP %d, want 200. A 401 or 403 means "+
			"the binding certificate was not presented on the TLS handshake, or the Authorization scheme was "+
			"not \"mtls_pop\". Response: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	fmt.Println("  OK: the resource accepted the certificate-bound token over mTLS.")
	return nil
}

// tracingMtlsClient builds the mutual-TLS client used for the token request and wraps its transport
// so the request can be described on screen. The transport mirrors what MSAL builds by default
// (binding certificate installed, TLS 1.2 floor); only the tracing wrapper is added.
func tracingMtlsClient(cert tls.Certificate) *http.Client {
	base := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}
	return &http.Client{Transport: traceTransport{base: base}}
}

// traceTransport prints what the mutual-TLS token request looks like on the wire. It exists so the
// two non-obvious claims about this flow can be observed rather than taken on faith: the token
// endpoint host is mtlsauth.*, not login.*, and the body carries no client_assertion.
//
// Only the token request travels on this transport. Instance and tenant discovery go over the
// ordinary HTTP client, so exactly one request is traced.
type traceTransport struct {
	base http.RoundTripper
}

func (t traceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	section("token request (mutual-TLS leg)")
	kv("method", req.Method)
	kv("endpoint host", req.URL.Host)
	kv("URL", req.URL.String())
	// GetBody hands back an independent reader, so inspecting the form does not consume the body MSAL
	// is about to send.
	if req.GetBody != nil {
		if body, err := req.GetBody(); err == nil {
			defer body.Close()
			if raw, err := io.ReadAll(body); err == nil {
				if form, err := url.ParseQuery(string(raw)); err == nil {
					names := make([]string, 0, len(form))
					for name := range form {
						names = append(names, name)
					}
					sort.Strings(names)
					// Parameter names only. No value is printed, so nothing sensitive can leak here
					// regardless of what the request grows later.
					kv("body parameters", strings.Join(names, ", "))
					kv("token_type requested", form.Get("token_type"))
					kv("client_assertion", label(form.Get("client_assertion") != "", "present", "absent"))
					kv("client_assertion_type", label(form.Get("client_assertion_type") != "", "present", "absent"))
					kv("req_cnf", label(form.Get("req_cnf") != "", "present", "absent"))
				}
			}
		}
	}
	fmt.Println("  The client certificate is presented on this handshake; that is what authenticates the")
	fmt.Println("  client and binds the token, which is why no client_assertion is needed.")
	return t.base.RoundTrip(req)
}

// The helpers below are duplicated rather than shared. A demo package shared across the mTLS pull
// request stack would couple every pull request in it to the others and leave none of them
// reviewable on its own, so roughly thirty lines of duplication is the deliberate trade-off. Each
// one is small, depends on nothing unmerged, and is used by this file.

// loadCertificate reads a PEM file holding a certificate and its private key and builds a
// NewCredFromCert credential from it, the same way apps/tests/integration/config_helpers_test.go
// does. It also returns the parsed leaf so the caller can compute the x5t#S256 thumbprint itself.
func loadCertificate(certPath string) (confidential.Credential, *x509.Certificate, error) {
	if strings.TrimSpace(certPath) == "" {
		return confidential.Credential{}, nil, fmt.Errorf(
			"no certificate supplied: pass -cert <path-to-pem> or set MTLS_CERT_PATH to a PEM file " +
				"containing the certificate and its private key")
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

// cnfThumbprintFromToken decodes an access token's JWT body and returns its cnf["x5t#S256"] claim,
// the thumbprint of the certificate the token is bound to. It mirrors checkTokenBoundToCertificate
// in apps/tests/integration/mtls_pop_integration_test.go. It returns an empty string rather than an
// error when the token carries no such claim, so the caller can report "unbound" in its own words.
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

// section prints a labelled banner so projected output is easy to follow on a screen.
func section(title string) {
	fmt.Println()
	fmt.Println("== " + title + " ==")
}

// kv prints an aligned "key: value" line.
func kv(key, value string) {
	fmt.Printf("  %-32s %s\n", key+":", value)
}

// label picks between two descriptions, keeping the output readable instead of printing true/false.
func label(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

// env returns the environment variable's value when set, otherwise def.
func env(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}
