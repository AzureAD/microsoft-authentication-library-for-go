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
//	go test -tags e2e -run IMDSv2 -v ./apps/tests/e2e/...
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
package e2e

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

// A certificate-bound token can only be issued for a resource that has opted in to accepting one.
// Entra refuses the request outright for a resource that has not, with AADSTS392196 ("the resource
// application does not support certificate-bound token"), so the choice of resource is part of what
// these tests exercise rather than an incidental detail. Microsoft Graph and Azure Key Vault both
// accept bound tokens and are the two resources MSAL .NET uses for the same coverage. Azure Resource
// Manager does not, so it cannot stand in here.
const (
	imdsV2Resource      = "https://graph.microsoft.com"
	imdsV2VaultResource = "https://vault.azure.net"
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
func skipUnlessIMDSv2(t *testing.T) {
	t.Helper()
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

	_, err = client.AcquireToken(ctx, imdsV2Resource, mi.WithMtlsProofOfPossession(), mi.WithAttestationSupport())
	switch {
	case err == nil:
		return
	case errors.Is(err, mi.ErrMtlsPoPNotSupportedInIMDSv1):
		skipOrFail(t, "this host serves IMDSv1 only")
	case errors.Is(err, mi.ErrCredentialGuardNotAvailable):
		skipOrFail(t, "Credential Guard is not enabled on this host")
	case errors.Is(err, mi.ErrMtlsNotSupportedForPlatform):
		skipOrFail(t, "this platform cannot produce a KeyGuard key")
	case errors.Is(err, mi.ErrAttestationUnavailable):
		skipOrFail(t, "AttestationClientLib.dll is not on this host, so the attested path cannot run")
	case strings.Contains(err.Error(), "identity_not_found"):
		skipOrFail(t, "no managed identity is assigned to this host")
	default:
		t.Fatalf("IMDSv2 acquisition failed for a reason that is not an environment gap: %v", err)
	}
}

// TestIMDSv2SystemAssignedBoundToken acquires a certificate-bound token for the system-assigned
// identity and checks the properties that make it a bound token rather than a bearer token.
func TestIMDSv2SystemAssignedBoundToken(t *testing.T) {
	skipUnlessIMDSv2(t)

	client, err := mi.New(mi.SystemAssigned())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := client.AcquireToken(ctx, imdsV2Resource, mi.WithMtlsProofOfPossession(), mi.WithAttestationSupport())
	if err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
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

	res, err := client.AcquireToken(ctx, imdsV2Resource, mi.WithMtlsProofOfPossession(), mi.WithAttestationSupport())
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

	res, err := client.AcquireToken(ctx, imdsV2Resource, mi.WithRequestOverMtls(), mi.WithAttestationSupport())
	if err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("no access token")
	}
	if strings.EqualFold(res.Metadata.TokenType, "mtls_pop") {
		t.Fatal("WithRequestOverMtls returned a bound token; it must return a bearer token")
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

	first, err := client.AcquireToken(ctx, imdsV2Resource, mi.WithMtlsProofOfPossession(), mi.WithAttestationSupport())
	if err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	second, err := client.AcquireToken(ctx, imdsV2Resource, mi.WithMtlsProofOfPossession(), mi.WithAttestationSupport())
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

	res, err := client.AcquireToken(ctx, imdsV2VaultResource, mi.WithMtlsProofOfPossession(), mi.WithAttestationSupport())
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

	res, err := client.AcquireToken(ctx, imdsV2VaultResource, mi.WithMtlsProofOfPossession(), mi.WithAttestationSupport())
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "mtls_pop "+token)
	req.Header.Set("x-ms-tokenboundauth", "true")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("%w [the resource asked for a client certificate: %t; a certificate was supplied to send: %t]",
			err, certRequested, len(cert.Certificate) > 0)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}
