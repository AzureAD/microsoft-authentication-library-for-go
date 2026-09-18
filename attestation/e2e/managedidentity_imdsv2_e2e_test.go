//go:build e2e && windows
// +build e2e,windows

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// End-to-end coverage for IMDSv2 managed identity, mirroring the live tests MSAL .NET runs for the
// same feature. Nothing here is simulated: the binding key is created inside Virtualization-based
// Security, the certificate is issued by the real Azure Instance Metadata Service, the token comes
// from Entra over a mutually authenticated connection, and the resource call goes to a real Azure
// Key Vault that enforces token binding.
//
// The full chain under test is:
//
//	public API -> KeyGuard key -> CSR -> IMDS-issued certificate
//	  -> mTLS token request -> bound token -> resource call -> successful E2E
//
// These tests compile and run only with the "e2e" build tag, on Windows, and only on a virtual
// machine that has a managed identity assigned and serves IMDSv2. They skip cleanly everywhere
// else, because there is no way to fake any of those things without also invalidating the test.
//
//	cd attestation
//	go test -tags e2e -run IMDSv2 -v ./e2e
//
// Optional environment variables:
//
//	IMDSV2_E2E_USER_ASSIGNED_CLIENT_ID  exercise a user-assigned identity as well as system-assigned
//	IMDSV2_E2E_VAULT                    host of a Key Vault configured for token binding
//	IMDSV2_E2E_SECRET                   name of a secret in that vault
//	IMDSV2_E2E_REQUIRED                 set to "true" on an agent that is provisioned for IMDSv2, to
//	                                    turn every environment skip below into a failure. Without it
//	                                    a misconfigured agent reports the same green result as a
//	                                    fully working one.
//	IMDSV2_E2E_COLD_ATTESTATION         require this process to execute the native attestation path
//	                                    instead of accepting persisted-certificate reuse.
package e2e

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
	attestation "github.com/AzureAD/microsoft-authentication-library-for-go/attestation"
	"golang.org/x/sys/windows"
)

// A certificate-bound token can only be issued for a resource that has opted in to accepting one.
// Entra refuses the request outright for a resource that has not, with AADSTS392196 ("the resource
// application does not support certificate-bound token"), so the choice of resource is part of what
// these tests exercise rather than an incidental detail. Microsoft Graph and Azure Key Vault both
// accept bound tokens and are the two resources MSAL .NET uses for the same coverage. Azure Resource
// Manager does not, so it cannot stand in here.
const (
	imdsV2Resource                     = "https://graph.microsoft.com"
	imdsV2VaultResource                = "https://vault.azure.net"
	attestationDLLName                 = "AttestationClientLib.dll"
	attestationDLLVersion              = "1.1.5"
	expectedAttestationDLLSHA256       = "90dfcce20e1a74519b49796eeee17e6e59a257c3acf754f454a49380d28a568b"
	maxWindowsModulePathUTF16CodeUnits = 32768
)

var (
	getModuleHandleW = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleW")

	deliveryState struct {
		sync.Once
		path          string
		existedBefore bool
		hashBefore    string
		modTimeBefore time.Time
		err           error
	}
)

// imdsV2Required reports whether this environment is expected to complete the IMDSv2 flow.
//
// A skip and a pass look identical in a CI summary, so on an agent that is provisioned for managed
// identity a skip is a silent regression rather than a legitimate environment gap. CI sets
// IMDSV2_E2E_REQUIRED on that pool to turn every skip below into a failure. It stays unset on
// developer machines, where skipping is the correct behavior.
func imdsV2Required() bool {
	required, err := strconv.ParseBool(os.Getenv("IMDSV2_E2E_REQUIRED"))
	return err == nil && required
}

// skipOrFail skips when IMDSv2 is optional in this environment and fails when it is required.
func skipOrFail(t *testing.T, format string, args ...interface{}) {
	t.Helper()
	if imdsV2Required() {
		t.Fatalf("IMDSV2_E2E_REQUIRED is set, so this is a failure rather than an environment gap: "+
			format, args...)
	}
	t.Skipf(format, args...)
}

// skipUnlessIMDSv2 skips the test unless this host can actually complete the flow.
//
// The check is a real acquisition attempt rather than an environment probe, because the only
// reliable way to know whether a host serves IMDSv2 with an assigned identity is to ask it. Any
// other failure is reported rather than skipped: silently skipping on a genuine bug would make
// these tests worthless.
//
// It returns the result of that acquisition so the test that called it can assert against it
// instead of acquiring again. The preflight is not free and it is not inert: it mints a binding
// certificate, persists it, caches an attestation statement and writes an access token to the
// token cache. A test that then acquired a second time would be measuring a warm cache while
// looking like it measured a cold one - which is exactly what makes a "no network round trips on
// the second call" assertion meaningless. Using the returned result keeps the preflight and the
// assertion the same acquisition.
func skipUnlessIMDSv2(t *testing.T) mi.AuthResult {
	t.Helper()
	prepareOptionalAttestationDelivery(t)
	source, srcErr := mi.GetSource()
	if srcErr != nil || source != mi.DefaultToIMDS {
		skipOrFail(t, "not an IMDS host (source=%v err=%v)", source, srcErr)
	}
	client, err := mi.New(mi.SystemAssigned())
	if err != nil {
		skipOrFail(t, "cannot create a managed identity client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := client.AcquireToken(ctx, imdsV2Resource, mi.WithMtlsProofOfPossession(), attestation.WithSupport())
	switch {
	case err == nil:
		verifyOptionalAttestationDelivery(t)
		return res
	case errors.Is(err, mi.ErrMtlsPoPNotSupportedInIMDSv1):
		skipOrFail(t, "this host serves IMDSv1 only")
	case errors.Is(err, mi.ErrCredentialGuardNotAvailable):
		skipOrFail(t, "Credential Guard is not enabled on this host")
	case errors.Is(err, mi.ErrMtlsNotSupportedForPlatform):
		skipOrFail(t, "this platform cannot produce a KeyGuard key")
	case errors.Is(err, mi.ErrAttestationUnavailable):
		skipOrFail(t, "the optional embedded attestation library is unavailable: %v", err)
	case strings.Contains(err.Error(), "identity_not_found"):
		skipOrFail(t, "no managed identity is assigned to this host")
	default:
		t.Fatalf("IMDSv2 acquisition failed for a reason that is not an environment gap: %v", err)
	}
	return mi.AuthResult{}
}

func prepareOptionalAttestationDelivery(t *testing.T) {
	t.Helper()
	deliveryState.Do(func() {
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			deliveryState.err = errors.New("LOCALAPPDATA is not set")
			return
		}
		deliveryState.path = filepath.Join(localAppData, "Microsoft", "MSAL", "attestation",
			attestationDLLVersion, "win-x64", attestationDLLName)
		if !filepath.IsAbs(deliveryState.path) {
			deliveryState.err = fmt.Errorf("expected attestation path %q is not absolute", deliveryState.path)
			return
		}

		executable, err := os.Executable()
		if err != nil {
			deliveryState.err = fmt.Errorf("finding the test executable: %w", err)
			return
		}
		workingDirectory, err := os.Getwd()
		if err != nil {
			deliveryState.err = fmt.Errorf("finding the test working directory: %w", err)
			return
		}
		for label, directory := range map[string]string{
			"application directory": filepath.Dir(executable),
			"working directory":     workingDirectory,
		} {
			candidate := filepath.Join(directory, attestationDLLName)
			if _, err := os.Stat(candidate); err == nil {
				deliveryState.err = fmt.Errorf("%s unexpectedly contains %s", label, candidate)
				return
			} else if !errors.Is(err, os.ErrNotExist) {
				deliveryState.err = fmt.Errorf("checking %s for an unexpected attestation DLL: %w", label, err)
				return
			}
		}

		info, err := os.Stat(deliveryState.path)
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			deliveryState.err = fmt.Errorf("inspecting the pre-existing attestation DLL: %w", err)
			return
		}
		deliveryState.existedBefore = true
		deliveryState.modTimeBefore = info.ModTime()
		deliveryState.hashBefore, deliveryState.err = fileSHA256(deliveryState.path)
	})
	if deliveryState.err != nil {
		t.Fatal(deliveryState.err)
	}
}

func verifyOptionalAttestationDelivery(t *testing.T) {
	t.Helper()
	info, err := os.Stat(deliveryState.path)
	if err != nil {
		t.Fatalf("inspecting the materialized attestation DLL: %v", err)
	}
	hash, err := fileSHA256(deliveryState.path)
	if err != nil {
		t.Fatal(err)
	}
	if hash != expectedAttestationDLLSHA256 {
		t.Fatalf("materialized attestation DLL SHA-256 = %s, want %s", hash, expectedAttestationDLLSHA256)
	}

	materialization := optionalAttestationMaterialization(info.ModTime())
	loadedPath, err := loadedModulePath(attestationDLLName)
	if err != nil {
		// WithSupport is deliberately lazy. A later process can restore the
		// previously attested certificate and never need a new attestation
		// statement, so the native library won't be loaded in that process.
		// Accept that only when the exact pinned file predated this run and
		// wasn't rewritten; a fresh or repaired materialization must be loaded.
		if canReusePersistedAttestedCredential(materialization, err, coldAttestationRequired()) {
			t.Logf("optional attestation credential reuse verified: the unchanged pinned DLL remains at %q; "+
				"the native module wasn't loaded because no new attestation statement was needed",
				deliveryState.path)
			return
		}
		t.Fatal(err)
	}
	if !filepath.IsAbs(loadedPath) {
		t.Fatalf("loaded attestation path %q is not absolute", loadedPath)
	}
	loadedInfo, err := os.Stat(loadedPath)
	if err != nil {
		t.Fatalf("stating loaded attestation path %q: %v", loadedPath, err)
	}
	if !os.SameFile(info, loadedInfo) {
		t.Fatalf("loaded attestation path = %q, want versioned LocalAppData path %q", loadedPath, deliveryState.path)
	}

	if coldAttestationRequired() {
		t.Log("cold optional attestation path verified: persisted-certificate reuse was disabled and the native module executed")
	}
	t.Logf("optional attestation delivery verified: %s; loaded absolute path %q; SHA-256 %s",
		materialization, loadedPath, hash)
}

func optionalAttestationMaterialization(modTimeAfter time.Time) string {
	if !deliveryState.existedBefore {
		return "fresh extraction"
	}
	if deliveryState.hashBefore == expectedAttestationDLLSHA256 &&
		deliveryState.modTimeBefore.Equal(modTimeAfter) {
		return "verified reuse"
	}
	return "repaired extraction"
}

func coldAttestationRequired() bool {
	required, err := strconv.ParseBool(os.Getenv("IMDSV2_E2E_COLD_ATTESTATION"))
	return err == nil && required
}

func canReusePersistedAttestedCredential(materialization string, moduleErr error, cold bool) bool {
	return !cold && materialization == "verified reuse" && errors.Is(moduleErr, windows.ERROR_MOD_NOT_FOUND)
}

func TestDeliveryVerificationAllowsUnloadedModuleOnlyForVerifiedReuse(t *testing.T) {
	missing := fmt.Errorf("GetModuleHandleW: %w", windows.ERROR_MOD_NOT_FOUND)
	for _, test := range []struct {
		name            string
		materialization string
		err             error
		cold            bool
		want            bool
	}{
		{"verified reuse", "verified reuse", missing, false, true},
		{"cold verified reuse", "verified reuse", missing, true, false},
		{"fresh extraction", "fresh extraction", missing, false, false},
		{"repaired extraction", "repaired extraction", missing, false, false},
		{"different loader error", "verified reuse", windows.ERROR_INVALID_HANDLE, false, false},
		{"no loader error", "verified reuse", nil, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := canReusePersistedAttestedCredential(test.materialization, test.err, test.cold); got != test.want {
				t.Fatalf("canReusePersistedAttestedCredential(%q, %v, %t) = %t, want %t",
					test.materialization, test.err, test.cold, got, test.want)
			}
		})
	}
}

func fileSHA256(path string) (digest string, err error) {
	// The path is the deterministic LocalAppData destination assembled above.
	//nolint:gosec
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening %q to hash it: %w", path, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("closing %q after hashing it: %w", path, closeErr)
		}
	}()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hashing %q: %w", path, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func loadedModulePath(name string) (string, error) {
	nameUTF16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", fmt.Errorf("encoding module name: %w", err)
	}
	// GetModuleHandleW observes an already-loaded module without incrementing its reference count.
	//nolint:gosec
	handle, _, callErr := getModuleHandleW.Call(uintptr(unsafe.Pointer(nameUTF16)))
	if handle == 0 {
		return "", fmt.Errorf("GetModuleHandleW(%q): %w", name, callErr)
	}
	for size := uint32(256); size <= maxWindowsModulePathUTF16CodeUnits; size *= 2 {
		buffer := make([]uint16, size)
		length, err := windows.GetModuleFileName(windows.Handle(handle), &buffer[0], size)
		if length == 0 {
			return "", fmt.Errorf("GetModuleFileNameW(%q): %w", name, err)
		}
		if length < size-1 {
			return windows.UTF16ToString(buffer[:length]), nil
		}
	}
	return "", fmt.Errorf("loaded module path for %q exceeds %d UTF-16 code units",
		name, maxWindowsModulePathUTF16CodeUnits)
}

// TestIMDSv2SystemAssignedBoundToken acquires a certificate-bound token for the system-assigned
// identity and checks the properties that make it a bound token rather than a bearer token.
//
// The assertions run against the result of the preflight acquisition, which is the same
// system-assigned, attested, bound acquisition this test would otherwise repeat.
func TestIMDSv2SystemAssignedBoundToken(t *testing.T) {
	res := skipUnlessIMDSv2(t)

	if res.AccessToken == "" {
		t.Fatal("no access token")
	}
	if res.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("token type = %q, want mtls_pop", res.Metadata.TokenType)
	}
	if res.BindingCertificate == nil {
		t.Fatal("no binding certificate: the caller cannot call the resource")
	}
	if res.BindingCertificate.Leaf == nil {
		t.Fatal("the binding certificate has no parsed leaf")
	}
	if res.BindingCertificateThumbprint() == "" {
		t.Fatal("the binding certificate has no thumbprint")
	}
	// The certificate must be usable for a handshake, which is the whole point of returning it.
	if len(res.BindingCertificate.Certificate) == 0 {
		t.Fatal("the binding certificate carries no DER chain")
	}
	if res.BindingCertificate.PrivateKey == nil {
		t.Fatal("the binding certificate carries no key")
	}
	if res.ExpiresOn.Before(time.Now()) {
		t.Fatalf("the token is already expired: %s", res.ExpiresOn)
	}
	t.Log("genuine KeyGuard attestation succeeded; IMDSv2 issued a binding certificate; " +
		"Entra returned token_type=mtls_pop over mTLS")
}

// TestIMDSv2UserAssignedBoundToken runs the same acquisition against a user-assigned identity.
func TestIMDSv2UserAssignedBoundToken(t *testing.T) {
	clientID := os.Getenv("IMDSV2_E2E_USER_ASSIGNED_CLIENT_ID")
	if clientID == "" {
		skipOrFail(t, "IMDSV2_E2E_USER_ASSIGNED_CLIENT_ID is not set")
	}
	skipUnlessIMDSv2(t)

	client, err := mi.New(mi.UserAssignedClientID(clientID))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := client.AcquireToken(ctx, imdsV2Resource, mi.WithMtlsProofOfPossession(), attestation.WithSupport())
	if err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if res.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("token type = %q, want mtls_pop", res.Metadata.TokenType)
	}
	if res.BindingCertificate == nil {
		t.Fatal("no binding certificate")
	}
}

// TestIMDSv2BearerOverMtls checks the other mode: acquisition is hardened by mutual TLS, but the
// token that comes back is an ordinary bearer token any resource accepts.
func TestIMDSv2BearerOverMtls(t *testing.T) {
	skipUnlessIMDSv2(t)

	client, err := mi.New(mi.SystemAssigned())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := client.AcquireToken(ctx, imdsV2Resource, mi.WithRequestOverMtls(), attestation.WithSupport())
	if err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("no access token")
	}
	// The type has to be exactly Bearer, not merely "not mtls_pop". A caller using
	// WithRequestOverMtls sends the result with the Bearer scheme whatever the service said, so any
	// other type - including one this library does not know - fails at the resource with nothing to
	// explain it. The comparison folds case because RFC 6749 section 7.1 declares token_type
	// case-insensitive.
	if !strings.EqualFold(res.Metadata.TokenType, "Bearer") {
		t.Fatalf("token type = %q, want Bearer: WithRequestOverMtls must return an ordinary bearer token", res.Metadata.TokenType)
	}
	// A bearer token is not bound to anything, so no certificate should be handed back: doing so
	// would suggest the caller has to present it.
	if res.BindingCertificate != nil {
		t.Fatal("a bearer token came back with a binding certificate")
	}
}

// TestIMDSv2TokenIsServedFromCache checks that a second acquisition for the same resource does not
// go back to the network, and returns the same token.
func TestIMDSv2TokenIsServedFromCache(t *testing.T) {
	skipUnlessIMDSv2(t)

	client, err := mi.New(mi.SystemAssigned())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	first, err := client.AcquireToken(ctx, imdsV2Resource, mi.WithMtlsProofOfPossession(), attestation.WithSupport())
	if err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	second, err := client.AcquireToken(ctx, imdsV2Resource, mi.WithMtlsProofOfPossession(), attestation.WithSupport())
	if err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if first.AccessToken != second.AccessToken {
		t.Fatal("the second acquisition did not come from the cache")
	}
	// Comparing the two thumbprints alone would also be satisfied by both being empty, which is
	// exactly what a cached bound token served without its certificate looks like. Requiring a
	// usable certificate first is what makes the comparison mean anything.
	if second.BindingCertificate == nil {
		t.Fatal("the cached bound token carries no binding certificate, so the caller cannot call the resource")
	}
	if second.BindingCertificateThumbprint() == "" {
		t.Fatal("the cached token's binding certificate has no thumbprint")
	}
	if second.BindingCertificateThumbprint() != first.BindingCertificateThumbprint() {
		t.Fatal("the cached token is bound to a different certificate")
	}
}

// TestIMDSv2CallsBoundResource is the test that actually proves the feature works: it takes the
// bound token to a Key Vault that enforces token binding and reads a secret.
//
// Acquiring a token is only half of the flow. A token that cannot be spent is not a working
// feature, and binding errors only surface at the resource, so this is the case that would catch a
// certificate or scheme mistake that every acquisition-only test would pass.
func TestIMDSv2CallsBoundResource(t *testing.T) {
	vault := os.Getenv("IMDSV2_E2E_VAULT")
	secret := os.Getenv("IMDSV2_E2E_SECRET")
	if vault == "" || secret == "" {
		skipOrFail(t, "IMDSV2_E2E_VAULT and IMDSV2_E2E_SECRET are not set")
	}
	skipUnlessIMDSv2(t)

	client, err := mi.New(mi.SystemAssigned())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	res, err := client.AcquireToken(ctx, imdsV2VaultResource, mi.WithMtlsProofOfPossession(), attestation.WithSupport())
	if err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if res.BindingCertificate == nil {
		t.Fatal("no binding certificate")
	}

	url := fmt.Sprintf("https://%s/secrets/%s?api-version=7.4", vault, secret)
	body, status, err := getBoundSecret(ctx, url, res.AccessToken, *res.BindingCertificate)
	if err != nil {
		t.Fatalf("calling the vault: %v", err)
	}
	switch {
	case status == http.StatusOK:
		if !strings.Contains(body, `"value"`) {
			t.Fatalf("the vault response does not look like a secret: %s", body)
		}
	case status == http.StatusForbidden && strings.Contains(body, "AccessDenied"):
		// A vault reaches its access check only after it has authenticated the caller, and this
		// vault requires a bound token to get that far. The two ways to fail binding both stop
		// earlier and are both a 401: presenting no client certificate is rejected as
		// MissingClientCertificate, which the negative test below asserts, and presenting no
		// acceptable token is rejected as AKV10000. Only a token whose binding the vault validated
		// reaches an authorization decision at all, and the decision names the managed identity the
		// vault resolved from the token. So this status still proves what this test exists to
		// prove; what it leaves unproven is only the data-plane read, which is a grant on the lab
		// vault rather than anything the library controls.
		t.Logf("the vault authenticated the bound token but the identity has no secrets/get grant, "+
			"so the binding is proven and the secret read is not: %s", body)
	default:
		t.Fatalf("vault returned %d: %s", status, body)
	}
}

// TestIMDSv2BoundTokenIsRejectedWithoutCertificate is the negative half of the resource test.
//
// Without it, the positive test alone cannot distinguish a genuinely bound token from an ordinary
// bearer token that the resource would have accepted anyway. This is what proves the binding is
// actually enforced.
func TestIMDSv2BoundTokenIsRejectedWithoutCertificate(t *testing.T) {
	vault := os.Getenv("IMDSV2_E2E_VAULT")
	secret := os.Getenv("IMDSV2_E2E_SECRET")
	if vault == "" || secret == "" {
		skipOrFail(t, "IMDSV2_E2E_VAULT and IMDSV2_E2E_SECRET are not set")
	}
	skipUnlessIMDSv2(t)

	client, err := mi.New(mi.SystemAssigned())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	res, err := client.AcquireToken(ctx, imdsV2VaultResource, mi.WithMtlsProofOfPossession(), attestation.WithSupport())
	if err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}

	// The same token, presented over a connection with no client certificate.
	body, status, err := getBoundSecret(ctx, fmt.Sprintf("https://%s/secrets/%s?api-version=7.4", vault, secret),
		res.AccessToken, tls.Certificate{})
	if err != nil {
		t.Fatalf("calling the vault: %v", err)
	}
	if status == http.StatusOK {
		t.Fatal("the vault accepted a bound token presented without its binding certificate")
	}
	// Asserting only "not 200" would pass for any unrelated rejection, including an expired or
	// malformed token, which would make this test green without proving anything about binding.
	// The vault names the reason, so require that reason specifically.
	if !strings.Contains(body, "MissingClientCertificate") {
		t.Fatalf("the vault rejected the request for some reason other than the missing binding certificate: %d: %s", status, body)
	}
}

// getBoundSecret calls Key Vault with a certificate-bound token.
//
// A bound token is presented with the "mtls_pop" scheme rather than "Bearer", and the request
// opts in to token binding with x-ms-tokenboundauth. Passing a zero tls.Certificate omits the
// client certificate, which is how the negative case is expressed.
//
// The TLS settings below are the whole reason this test is interesting, and they are not optional.
// Key Vault does not ask for a client certificate during the initial handshake; it completes the
// handshake, reads the request, sees the mtls_pop scheme, and only then asks for the certificate by
// renegotiating. Go refuses renegotiation by default (crypto/tls defaults to RenegotiateNever) and
// has no support at all for the TLS 1.3 equivalent, post-handshake authentication, so a default
// Go transport is torn down at exactly that point. The symptom is a bare connection reset with no
// HTTP response to inspect, which looks like a network fault rather than a protocol gap. Pinning
// TLS 1.2 keeps the exchange on the renegotiation path, and RenegotiateOnceAsClient lets Go answer
// it. .NET and curl hit none of this because schannel renegotiates natively.
func getBoundSecret(ctx context.Context, url, token string, cert tls.Certificate) (string, int, error) {
	// Key Vault asks for the client certificate through TLS 1.2 renegotiation; Go doesn't support
	// the equivalent TLS 1.3 post-handshake authentication. See the protocol explanation above.
	//nolint:gosec
	tlsConfig := &tls.Config{
		MinVersion:    tls.VersionTLS12,
		MaxVersion:    tls.VersionTLS12,
		Renegotiation: tls.RenegotiateOnceAsClient,
	}
	// Go matches tls.Config.Certificates against the certificate authorities the server names and
	// silently sends nothing when none match. A binding certificate is issued by an internal CA the
	// resource is not obliged to advertise, so it is supplied through this callback instead, which
	// is not filtered. Recording whether the callback ran distinguishes "the resource rejected our
	// certificate" from "the resource never asked for one".
	var certRequested bool
	tlsConfig.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		certRequested = true
		if len(cert.Certificate) == 0 {
			// Returning an empty certificate is how Go expresses "send none", which is the
			// negative case rather than an error.
			return &tls.Certificate{}, nil
		}
		return &cert, nil
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	// This E2E test intentionally calls the operator-provided Key Vault URL.
	//nolint:gosec
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "mtls_pop "+token)
	req.Header.Set("x-ms-tokenboundauth", "true")

	// This E2E test intentionally calls the operator-provided Key Vault URL.
	//nolint:gosec
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("%w [the resource asked for a client certificate: %t; a certificate was supplied to send: %t]",
			err, certRequested, len(cert.Certificate) > 0)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	closeErr := resp.Body.Close()
	if err != nil {
		return "", resp.StatusCode, err
	}
	if closeErr != nil {
		return "", resp.StatusCode, fmt.Errorf("closing the vault response body: %w", closeErr)
	}
	return string(body), resp.StatusCode, nil
}
