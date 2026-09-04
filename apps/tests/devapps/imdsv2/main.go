// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Command imdsv2 is a runnable demonstration of managed identity over IMDSv2: a managed identity
// access token that is cryptographically bound to a certificate whose private key is isolated by
// Windows KeyGuard (virtualization-based security), rather than a plain bearer token that anyone
// who obtains it can replay.
//
// The opt-in is one per-call option:
//
//	client, _ := managedidentity.New(managedidentity.SystemAssigned())
//	res, _ := client.AcquireToken(ctx, "https://vault.azure.net",
//		managedidentity.WithMtlsProofOfPossession())
//
// and the result carries everything needed to use the token:
//
//	res.Metadata.TokenType             == "mtls_pop"  (not "Bearer")
//	res.BindingCertificate                            the chain plus the live private key
//	res.BindingCertificateThumbprint() == the token's cnf["x5t#S256"] claim
//
// Behind that one option MSAL makes three requests before Entra is ever reached: it asks IMDS for
// platform metadata, mints a KeyGuard key and exchanges a CSR for a short-lived client certificate,
// then uses that certificate to authenticate the mutual-TLS handshake to Entra. Run with -trace to
// watch the last of those legs.
//
// This program is deliberately useful on a host that cannot do any of it. It always reports host
// capabilities first, and it explains every failure in terms of what is missing and what would fix
// it, so running it on a laptop, a Linux container or a VM without Credential Guard is an
// informative outcome rather than an opaque error.
//
// Run with -h for flags. No token, certificate or key is ever printed.
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	msalerrors "github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

const (
	// defaultResource is a managed identity resource, not a scope: managed identity takes the bare
	// resource URI and MSAL appends /.default itself.
	defaultResource = "https://vault.azure.net"

	// keyVaultExample is a known-good shape for -call on a VM whose identity has been granted access
	// to a vault. Key Vault is the useful example precisely because it asks for the client
	// certificate by renegotiating, which is the case most likely to be got wrong.
	keyVaultExample = "https://<your-vault>.vault.azure.net/secrets?api-version=7.4"
)

// config holds everything the demo reads from flags or the environment.
type config struct {
	idKind       string
	idValue      string
	resource     string
	mode         string
	call         string
	attest       bool
	minStrength  string
	forceRefresh bool
	capsOnly     bool
	clientCaps   string
	trace        bool
}

func main() {
	var cfg config
	flag.StringVar(&cfg.idKind, "id-type", env("MI_ID_TYPE", "system"),
		`identity to use: "system", or "client", "resource" or "object" for a user-assigned identity`)
	flag.StringVar(&cfg.idValue, "id", env("MI_ID", ""),
		"the client ID, resource ID or object ID, when -id-type is not system")
	flag.StringVar(&cfg.resource, "resource", env("MI_RESOURCE", defaultResource),
		"resource URI to request a token for")
	flag.StringVar(&cfg.mode, "mode", env("MI_MODE", "pop"),
		`"pop" for a certificate-bound mtls_pop token, "bearer-mtls" for a bearer token acquired `+
			`over mTLS, or "plain" for ordinary IMDSv1 managed identity`)
	flag.StringVar(&cfg.call, "call", env("MI_CALL", ""),
		"optional resource URL to call with the token; empty means acquire only")
	flag.BoolVar(&cfg.attest, "attest", false,
		"require the binding key to be attested before the credential is issued")
	flag.StringVar(&cfg.minStrength, "min-strength", "",
		`refuse to mint unless the host can bind at least this strongly: "software" or "keyguard"`)
	flag.BoolVar(&cfg.forceRefresh, "force-refresh", false,
		"bypass the token cache for this request")
	flag.BoolVar(&cfg.capsOnly, "capabilities-only", false,
		"report what this host can do and exit without acquiring a token")
	flag.StringVar(&cfg.clientCaps, "client-capabilities", env("MI_CLIENT_CAPABILITIES", ""),
		`comma-separated client capabilities sent to Entra, for example "cp1"`)
	flag.BoolVar(&cfg.trace, "trace", false,
		"print the mutual-TLS token request's endpoint host (never any token or key material)")
	flag.Parse()

	if err := run(cfg); err != nil {
		reportError(err)
		os.Exit(1)
	}
}

// reportError prints the concise error, then whatever extra detail is genuinely available.
//
// errors.Verbose is deliberately not used for the headline: it concatenates every level of the
// chain, and because fmt.Errorf("...: %w") already embeds the wrapped message, that prints the same
// sentence twice. The concise error plus errors.As for the HTTP detail is the pattern the errors
// package documents.
func reportError(err error) {
	fmt.Fprintf(os.Stderr, "\nimdsv2: %v\n", err)

	explain(err)

	var callErr msalerrors.CallErr
	if errors.As(err, &callErr) && callErr.Resp != nil {
		sectionTo(os.Stderr, "http detail")
		kvTo(os.Stderr, "status", callErr.Resp.Status)
		if callErr.Req != nil {
			kvTo(os.Stderr, "request", callErr.Req.Method+" "+callErr.Req.URL.String())
		}
		fmt.Fprintln(os.Stderr, "  errors.As(err, &errors.CallErr{}) exposes the request and response, and")
		fmt.Fprintln(os.Stderr, "  errors.Verbose(err) prints them in full.")
	}
}

func run(cfg config) error {
	ctx := context.Background()

	id, err := identity(cfg.idKind, cfg.idValue)
	if err != nil {
		return err
	}

	var clientOpts []managedidentity.ClientOption
	if caps := splitList(cfg.clientCaps); len(caps) > 0 {
		// Client capabilities travel to Entra on the token request and are how a resource learns
		// this client can handle a claims challenge. They are a client-wide setting, not per call.
		clientOpts = append(clientOpts, managedidentity.WithClientCapabilities(caps))
	}
	if cfg.trace {
		// WithMtlsHTTPClient overrides how the mutual-TLS client is built for the Entra leg. It is
		// the escape hatch for a caller who must own that handshake; here it is used only to
		// observe the request. The transport it builds mirrors MSAL's own.
		clientOpts = append(clientOpts, managedidentity.WithMtlsHTTPClient(tracingMtlsClient))
	}

	client, err := managedidentity.New(id, clientOpts...)
	if err != nil {
		return fmt.Errorf("managedidentity.New failed: %w", err)
	}

	// Validate the per-request flags before the capability probe, so a typo fails immediately
	// rather than after a network round-trip to IMDS.
	opts, err := acquireOptions(cfg)
	if err != nil {
		return err
	}

	if err := reportCapabilities(ctx, client); err != nil {
		return err
	}
	if cfg.capsOnly {
		return nil
	}

	section("acquiring")
	kv("identity", describeIdentity(cfg))
	kv("resource", cfg.resource)
	kv("mode", describeMode(cfg.mode))
	kv("options", describeOptions(cfg))

	result, err := client.AcquireToken(ctx, cfg.resource, opts...)
	if err != nil {
		return fmt.Errorf("AcquireToken failed: %w", err)
	}

	if err := reportResult(cfg, result); err != nil {
		return err
	}
	return useToken(cfg, result)
}

// reportCapabilities asks what this host can do before committing to an acquisition. This is the
// call a credential chain makes to decide whether to try managed identity at all, and it is the
// first thing this program does because it explains most failures before they happen.
func reportCapabilities(ctx context.Context, client managedidentity.Client) error {
	section("host capabilities")
	kv("GOOS", runtime.GOOS)

	caps, err := client.Capabilities(ctx)
	if err != nil {
		return fmt.Errorf("Capabilities failed: %w", err)
	}

	kv("Source", label(caps.Source != "", string(caps.Source), "(none detected)"))
	kv("MaxSupportedBindingStrength", caps.MaxSupportedBindingStrength.String())
	kv("IsMtlsPoPSupportedByHost()", label(caps.IsMtlsPoPSupportedByHost(), "true", "false"))
	if caps.ErrorReason != "" {
		kv("ErrorReason", caps.ErrorReason)
	}

	switch {
	case caps.IsMtlsPoPSupportedByHost():
		fmt.Println("  This host can mint a KeyGuard-bound credential, so -mode pop should succeed.")
	case caps.MaxSupportedBindingStrength == managedidentity.MtlsBindingStrengthSoftware:
		fmt.Println("  This host reports a software key only. Capabilities reports what the platform")
		fmt.Println("  offers; an mTLS PoP acquisition still fails, because IMDSv2 accepts nothing")
		fmt.Println("  weaker than KeyGuard rather than issuing a token that only looks bound.")
	default:
		fmt.Println("  This host cannot bind a token. -mode plain still works; -mode pop will fail")
		fmt.Println("  with a specific error explaining what is missing.")
	}
	return nil
}

// acquireOptions turns the flags into per-request options. Every one of these is per call: the same
// client hands out ordinary bearer tokens when they are omitted.
func acquireOptions(cfg config) ([]managedidentity.AcquireTokenOption, error) {
	var opts []managedidentity.AcquireTokenOption

	switch strings.ToLower(strings.TrimSpace(cfg.mode)) {
	case "pop":
		opts = append(opts, managedidentity.WithMtlsProofOfPossession())
	case "bearer-mtls":
		opts = append(opts, managedidentity.WithRequestOverMtls())
	case "plain":
		// Nothing to add. This is ordinary IMDSv1 managed identity, unchanged.
	default:
		return nil, fmt.Errorf("unknown -mode %q: want pop, bearer-mtls or plain", cfg.mode)
	}

	if cfg.attest {
		opts = append(opts, managedidentity.WithAttestationSupport())
	}
	if cfg.minStrength != "" {
		s, err := strengthFromName(cfg.minStrength)
		if err != nil {
			return nil, err
		}
		opts = append(opts, managedidentity.WithMtlsPoPMinStrength(s))
	}
	if cfg.forceRefresh {
		opts = append(opts, managedidentity.WithForceRefresh())
	}
	return opts, nil
}

// reportResult prints what came back and then checks it, so the two claims that matter are observed
// rather than taken on faith: the token type is what was asked for, and a bound token's thumbprint
// really does match the cnf claim inside the token.
func reportResult(cfg config, result managedidentity.AuthResult) error {
	section("result")
	kv("Metadata.TokenType", result.Metadata.TokenType)
	kv("BindingCertificate", label(result.BindingCertificate != nil,
		"present (chain plus live private key)", "nil"))
	if result.BindingCertificate != nil && result.BindingCertificate.Leaf != nil {
		kv("BindingCertificate.Leaf.Subject", result.BindingCertificate.Leaf.Subject.CommonName)
		kv("BindingCertificate.NotAfter", result.BindingCertificate.Leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	kv("BindingCertificateThumbprint()", label(result.BindingCertificateThumbprint() != "",
		result.BindingCertificateThumbprint(), "(none: token is not bound)"))
	// The access token itself is never printed. Its cnf claim is the interesting part, and is public.
	kv("access token length", fmt.Sprintf("%d characters (not printed)", len(result.AccessToken)))
	kv("expires on", result.ExpiresOn.UTC().Format(time.RFC3339))

	mode := strings.ToLower(strings.TrimSpace(cfg.mode))
	section("verification")

	if mode != "pop" {
		// Bearer-over-mTLS hardens acquisition without asking the resource to learn a new token
		// type. The token genuinely is an ordinary bearer token, so a nil BindingCertificate is the
		// correct answer and is what stops a caller mistaking it for a bound one.
		if result.BindingCertificate != nil {
			return fmt.Errorf("expected no binding certificate for -mode %s, got one", mode)
		}
		fmt.Println("  OK: an ordinary bearer token, with no binding certificate, as expected.")
		if mode == "bearer-mtls" {
			fmt.Println("  The hardening here is in how the token was acquired, not in the token itself.")
		}
		return nil
	}

	cnf, err := cnfThumbprintFromToken(result.AccessToken)
	if err != nil {
		return fmt.Errorf("could not read the cnf claim from the token: %w", err)
	}
	if cnf == "" {
		return fmt.Errorf(`the token carries no cnf["x5t#S256"] claim, so it is not certificate-bound`)
	}
	kv(`token cnf["x5t#S256"]`, cnf)

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
	fmt.Println("  The private key behind that certificate is held by KeyGuard and cannot be exported,")
	fmt.Println("  so a stolen token cannot be replayed: the thief cannot complete the handshake.")
	return nil
}

// useToken shows the half of the flow MSAL cannot do for the caller. Redeeming an mtls_pop token
// takes both halves and neither works alone: the binding certificate goes on the connection, and
// the token goes in the Authorization header under the mtls_pop scheme rather than Bearer.
//
// Two settings here are easy to miss, and both fail as a bare connection reset rather than as an
// error that can be read:
//
//   - GetClientCertificate rather than Certificates. Go filters Certificates against the certificate
//     authorities the server advertises and silently sends nothing when none match.
//     GetClientCertificate is not filtered.
//   - TLS 1.2 with client renegotiation allowed. A resource that enforces token binding is free to
//     complete the handshake, read the request, see the mtls_pop scheme, and only then ask for the
//     certificate by renegotiating. Go declines renegotiation by default and crypto/tls does not
//     implement post-handshake authentication, the TLS 1.3 equivalent.
func useToken(cfg config, result managedidentity.AuthResult) error {
	if strings.ToLower(strings.TrimSpace(cfg.mode)) != "pop" {
		if cfg.call != "" {
			fmt.Println()
			fmt.Println("  -call is only demonstrated for -mode pop, where the certificate is the point.")
		}
		return nil
	}

	section("using the token")

	// The certificate is used exactly as MSAL returned it. Copying the value and closing over the
	// copy is deliberate: the reference that keeps the private key alive travels with it.
	cert := *result.BindingCertificate
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			// #nosec G402 -- MaxVersion is pinned to TLS 1.2 deliberately. Go implements
			// renegotiation only for TLS 1.2, which is what lets a resource ask for the client
			// certificate after reading the request. See the comment above.
			TLSClientConfig: &tls.Config{
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &cert, nil
				},
				MinVersion:    tls.VersionTLS12,
				MaxVersion:    tls.VersionTLS12,
				Renegotiation: tls.RenegotiateOnceAsClient,
			},
		},
	}

	kv("tls.Config.GetClientCertificate", "returns result.BindingCertificate")
	kv("tls.Config.Renegotiation", "RenegotiateOnceAsClient (TLS 1.2)")
	kv("Authorization header", `"mtls_pop " + result.AccessToken`)
	kv("x-ms-tokenboundauth", "true")

	if cfg.call == "" {
		fmt.Println("  The client above is built but not sent; pass -call <url> to send it.")
		fmt.Printf("  A vault your identity can read is a good target:\n    -call %q\n", keyVaultExample)
		return nil
	}
	kv("resource", cfg.call)

	req, err := http.NewRequest(http.MethodGet, cfg.call, nil)
	if err != nil {
		return fmt.Errorf("building the resource request failed: %w", err)
	}
	// Not "Bearer". A resource expecting proof-of-possession rejects the wrong scheme.
	req.Header.Set("Authorization", "mtls_pop "+result.AccessToken)
	// Tells the resource this client is presenting a bound token, so it asks for the certificate.
	req.Header.Set("x-ms-tokenboundauth", "true")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("mTLS resource call to %s failed: %w", cfg.call, err)
	}
	defer resp.Body.Close()

	kv("HTTP status", resp.Status)
	if resp.StatusCode != http.StatusOK {
		// Truncate the external response rather than dumping an arbitrary payload onto the screen.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("the resource did not accept the token: got HTTP %d, want 200. A 401 or 403 "+
			"means the binding certificate was not presented on the TLS handshake, the Authorization "+
			"scheme was not \"mtls_pop\", or this identity lacks access. Response: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}
	fmt.Println("  OK: the resource accepted the certificate-bound token over mTLS.")
	return nil
}

// explain turns a sentinel error into what is wrong and what would fix it. Every failure mode of
// this feature is environmental - wrong OS, virtualization-based security off, an IMDSv1-only host,
// a missing native library - and each has a different remedy, which is why they are distinct
// sentinels rather than one error a caller would have to string-match.
func explain(err error) {
	diagnostics := []struct {
		sentinel error
		name     string
		cause    string
		fix      string
	}{
		{
			managedidentity.ErrMtlsNotSupportedForPlatform,
			"ErrMtlsNotSupportedForPlatform",
			"mTLS proof-of-possession needs a KeyGuard key, and only Windows CNG exposes one.",
			"Run on Windows, or use -mode plain. There is deliberately no software fallback: it " +
				"would produce a token that looks bound but is not.",
		},
		{
			managedidentity.ErrCredentialGuardNotAvailable,
			"ErrCredentialGuardNotAvailable",
			"This is Windows, but virtualization-based security is not protecting keys, so no " +
				"KeyGuard key can be created.",
			"Enable Credential Guard / VBS. On Azure that means a Trusted Launch or confidential VM.",
		},
		{
			managedidentity.ErrMtlsPoPNotSupportedInIMDSv1,
			"ErrMtlsPoPNotSupportedInIMDSv1",
			"The IMDS endpoint on this host answers the v1 token API but has no credential " +
				"issuance endpoint, so there is nothing to mint a certificate from.",
			"Use a VM whose IMDS supports v2, or use -mode plain.",
		},
		{
			managedidentity.ErrMtlsPoPNotSupportedForSource,
			"ErrMtlsPoPNotSupportedForSource",
			"This managed identity source has no credential issuance endpoint at all.",
			"App Service, Service Fabric, Cloud Shell, Azure ML and Azure Arc cannot do IMDSv2. " +
				"Use -mode plain there.",
		},
		{
			managedidentity.ErrMtlsPoPAndBearerExclusive,
			"ErrMtlsPoPAndBearerExclusive",
			"One request asked for both a bound token and a bearer token.",
			"Pass one of -mode pop or -mode bearer-mtls, not both.",
		},
		{
			managedidentity.ErrAttestationUnavailable,
			"ErrAttestationUnavailable",
			"Attestation was required but this host cannot produce an attested KeyGuard key.",
			"AttestationClientLib.dll must be present in the application directory or System32. " +
				"Drop -attest to issue an unattested credential instead.",
		},
		{
			managedidentity.ErrAttestationRequiresMtls,
			"ErrAttestationRequiresMtls",
			"-attest only means something on a path that mints a binding key.",
			"Combine -attest with -mode pop or -mode bearer-mtls.",
		},
		{
			managedidentity.ErrMinStrengthNotMet,
			"ErrMinStrengthNotMet",
			"This host cannot bind a token as strongly as -min-strength demanded.",
			"Lower -min-strength, or run on a host with Credential Guard enabled. Failing here is " +
				"the point: the alternative is a weaker token than the caller asked for.",
		},
		{
			managedidentity.ErrMinStrengthRequiresMtls,
			"ErrMinStrengthRequiresMtls",
			"-min-strength only means something on a path that mints a binding key.",
			"Combine -min-strength with -mode pop or -mode bearer-mtls.",
		},
	}

	for _, d := range diagnostics {
		if errors.Is(err, d.sentinel) {
			sectionTo(os.Stderr, "what this means")
			kvTo(os.Stderr, "cause", d.cause)
			kvTo(os.Stderr, "fix", d.fix)
			fmt.Fprintf(os.Stderr, "\n  Match this in code with errors.Is(err, managedidentity.%s).\n", d.name)
			return
		}
	}
}

// tracingMtlsClient builds the mutual-TLS client used for the Entra token request and wraps its
// transport so the request can be described on screen. The transport mirrors what MSAL builds by
// default; only the tracing wrapper is added.
func tracingMtlsClient(cert tls.Certificate) *http.Client {
	base := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}
	return &http.Client{Transport: traceTransport{base: base}}
}

// traceTransport prints what the mutual-TLS token request looks like on the wire, so the
// non-obvious claim about this flow can be observed rather than taken on faith: the token endpoint
// host is mtlsauth.*, not login.*, and the IMDS-issued certificate is what authenticates it.
type traceTransport struct {
	base http.RoundTripper
}

func (t traceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	section("token request (mutual-TLS leg to Entra)")
	kv("method", req.Method)
	kv("endpoint host", req.URL.Host)
	fmt.Println("  The IMDS-issued client certificate is presented on this handshake. That is what")
	fmt.Println("  authenticates the identity and binds the token, so no client secret is involved.")
	return t.base.RoundTrip(req)
}

// identity turns the -id-type and -id flags into a managed identity ID.
func identity(kind, value string) (managedidentity.ID, error) {
	value = strings.TrimSpace(value)
	k := strings.ToLower(strings.TrimSpace(kind))
	switch k {
	case "", "system":
		if value != "" {
			return nil, fmt.Errorf("-id is meaningless with -id-type system; drop one of them")
		}
		return managedidentity.SystemAssigned(), nil
	case "client", "resource", "object":
		if value == "" {
			return nil, fmt.Errorf("-id-type %s needs -id <value>", k)
		}
		switch k {
		case "client":
			return managedidentity.UserAssignedClientID(value), nil
		case "resource":
			return managedidentity.UserAssignedResourceID(value), nil
		default:
			return managedidentity.UserAssignedObjectID(value), nil
		}
	default:
		return nil, fmt.Errorf("unknown -id-type %q: want system, client, resource or object", kind)
	}
}

// strengthFromName parses -min-strength. Numeric values are deliberately not accepted: the constants
// are not contiguous, so a caller writing a number is a caller about to be surprised.
func strengthFromName(name string) (managedidentity.MtlsBindingStrength, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "none":
		return managedidentity.MtlsBindingStrengthNone, nil
	case "software":
		return managedidentity.MtlsBindingStrengthSoftware, nil
	case "keyguard":
		return managedidentity.MtlsBindingStrengthKeyGuard, nil
	default:
		return 0, fmt.Errorf("unknown -min-strength %q: want none, software or keyguard", name)
	}
}

func describeIdentity(cfg config) string {
	if k := strings.ToLower(strings.TrimSpace(cfg.idKind)); k == "" || k == "system" {
		return "system-assigned"
	}
	return fmt.Sprintf("user-assigned by %s ID", strings.ToLower(strings.TrimSpace(cfg.idKind)))
}

func describeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "pop":
		return "mtls_pop (certificate-bound token, IMDSv2)"
	case "bearer-mtls":
		return "bearer over mTLS (hardened acquisition, ordinary token)"
	default:
		return "plain (IMDSv1, unchanged)"
	}
}

func describeOptions(cfg config) string {
	var on []string
	if cfg.attest {
		on = append(on, "WithAttestationSupport()")
	}
	if cfg.minStrength != "" {
		on = append(on, "WithMtlsPoPMinStrength("+strings.ToLower(strings.TrimSpace(cfg.minStrength))+")")
	}
	if cfg.forceRefresh {
		on = append(on, "WithForceRefresh()")
	}
	if len(on) == 0 {
		return "(none beyond the mode)"
	}
	return strings.Join(on, ", ")
}

// cnfThumbprintFromToken decodes an access token's JWT body and returns its cnf["x5t#S256"] claim,
// the thumbprint of the certificate the token is bound to. It returns an empty string rather than
// an error when the token carries no such claim, so the caller can report "unbound" in its own
// words.
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

// splitList parses a comma-separated flag value into its non-empty entries.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// section prints a labelled banner so projected output is easy to follow on a screen.
func section(title string) { sectionTo(os.Stdout, title) }

// kv prints an aligned "key: value" line.
func kv(key, value string) { kvTo(os.Stdout, key, value) }

// sectionTo and kvTo write to an explicit stream. The error path uses stderr for everything it
// prints, so the diagnosis cannot interleave ahead of the error it is diagnosing.
func sectionTo(w io.Writer, title string) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "== "+title+" ==")
}

func kvTo(w io.Writer, key, value string) {
	fmt.Fprintf(w, "  %-32s %s\n", key+":", value)
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
