// mTLS PoP Manual Test — Path 1: Confidential Client (SNI Certificate)
//
// Tests both the happy path (requires Azure AD app registration + cert upload)
// and all error cases (no credentials required).
//
// Usage:
//   # Error cases only (no Azure credentials needed):
//   go run . -errors-only
//
//   # Full test (requires Azure app registration):
//   go run . -tenant <tenantID> -client <clientID> -region <region>
//
// Cert files (test-cert.pem, test-key.pem) must be in the parent directory (mtls-pop/).
// test-cert.pem is committed to the repo; test-key.pem is gitignored — generate it with:
//
//	openssl req -x509 -newkey rsa:2048 -keyout ../test-key.pem -out ../test-cert.pem \
//	  -days 365 -nodes -subj "/CN=msal-go-mtls-test"
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/tests/devapps/mtls-pop/internal/jwtutil"
)

func main() {
	tenantID := flag.String("tenant", "", "Azure AD tenant ID")
	clientID := flag.String("client", "", "Azure AD application (client) ID")
	region := flag.String("region", "centraluseuap", "Azure region for mTLS endpoint (e.g. westus2)")
	resource := flag.String("resource", "https://graph.microsoft.com", "Downstream resource URL to call after acquiring token (optional)")
	errorsOnly := flag.Bool("errors-only", false, "Only run error-case validation (no Azure credentials required)")
	flag.Parse()

	// Cert files are in the parent directory (mtls-pop/)
	certDir := filepath.Join(filepath.Dir(os.Args[0]), "..")
	// Also try relative to working directory
	certPEM, err := os.ReadFile(filepath.Join("..", "test-cert.pem"))
	if err != nil {
		certPEM, err = os.ReadFile(filepath.Join(certDir, "test-cert.pem"))
		if err != nil {
			log.Fatalf("read cert (tried ../test-cert.pem and %s): %v", filepath.Join(certDir, "test-cert.pem"), err)
		}
	}
	keyPEM, err := os.ReadFile(filepath.Join("..", "test-key.pem"))
	if err != nil {
		keyPEM, err = os.ReadFile(filepath.Join(certDir, "test-key.pem"))
		if err != nil {
			log.Fatalf("read key: %v", err)
		}
	}

	certs, key, err := confidential.CertFromPEM(append(certPEM, keyPEM...), "")
	if err != nil {
		log.Fatalf("parse cert+key: %v", err)
	}
	cred, err := confidential.NewCredFromCert(certs, key)
	if err != nil {
		log.Fatalf("create cred: %v", err)
	}

	fmt.Println("=== Path 1: Error-Case Validation ===")
	testErrorCases(cred, *tenantID, *clientID, *region)

	if *errorsOnly {
		fmt.Println("\n[Skipping happy-path test: -errors-only flag set]")
		fmt.Println("To run the happy path, register an Azure AD app and upload the certificate at")
		fmt.Println("  ../test-cert.pem")
		fmt.Println("then run:")
		fmt.Printf("  go run . -tenant <tenantID> -client <clientID> -region %s\n", *region)
		return
	}

	if *tenantID == "" || *clientID == "" {
		fmt.Println("\n[Skipping happy-path test: -tenant and -client flags required]")
		fmt.Println("Run with -errors-only to test only error cases, or provide -tenant/-client for the full test.")
		os.Exit(1)
	}

	fmt.Println("\n=== Path 1: Happy Path ===")
	testHappyPath(cred, certPEM, keyPEM, *tenantID, *clientID, *region, *resource)
}

func testErrorCases(cred confidential.Credential, tenantID, clientID, region string) {
	ctx := context.Background()
	// Use a tenanted authority for error-case validation. Errors are caught before any
	// network call, so the actual tenant value doesn't matter — just needs to be a GUID.
	// Prefer the -tenant flag, then AZURE_TENANT_ID env var, then a safe placeholder.
	errorTenant := tenantID
	if errorTenant == "" {
		errorTenant = os.Getenv("AZURE_TENANT_ID")
	}
	if errorTenant == "" {
		errorTenant = "00000000-0000-0000-0000-000000000000"
	}
	authority := "https://login.microsoftonline.com/" + errorTenant
	cID := clientID
	if cID == "" {
		cID = "00000000-0000-0000-0000-000000000000" // placeholder — errors trigger before network call
	}

	pass := 0
	fail := 0

	check := func(name, wantErrContains string, err error) {
		if err == nil {
			fmt.Printf("  ❌ FAIL [%s]: expected error containing %q, got nil\n", name, wantErrContains)
			fail++
			return
		}
		if strings.Contains(err.Error(), wantErrContains) {
			fmt.Printf("  ✅ PASS [%s]: got expected error: %v\n", name, err)
			pass++
		} else {
			fmt.Printf("  ❌ FAIL [%s]: expected error containing %q, got: %v\n", name, wantErrContains, err)
			fail++
		}
	}

	// NOTE: The errors package defines code constants like "mtls_pop_no_region" but the
	// actual error messages currently use plain-English text. Tests check the actual messages.

	// Error case 1: missing region
	client1, err := confidential.New(authority, cID, cred) // no WithAzureRegion
	if err != nil {
		fmt.Printf("  ❌ FAIL [no-region setup]: unexpected error creating client: %v\n", err)
		fail++
	} else {
		_, err = client1.AcquireTokenByCredential(ctx, []string{"https://graph.microsoft.com/.default"},
			confidential.WithMtlsProofOfPossession())
		check("missing-region", "mTLS PoP requires an Azure region", err)
	}

	// Error case 2: non-tenanted authority (/common)
	client2, err := confidential.New("https://login.microsoftonline.com/common", cID, cred,
		confidential.WithAzureRegion(region))
	if err != nil {
		fmt.Printf("  ❌ FAIL [common-authority setup]: unexpected error: %v\n", err)
		fail++
	} else {
		_, err = client2.AcquireTokenByCredential(ctx, []string{"https://graph.microsoft.com/.default"},
			confidential.WithMtlsProofOfPossession())
		check("non-tenanted-authority(/common)", "mTLS PoP requires a tenanted authority", err)
	}

	// Error case 3: non-tenanted authority (/organizations)
	client3, err := confidential.New("https://login.microsoftonline.com/organizations", cID, cred,
		confidential.WithAzureRegion(region))
	if err != nil {
		fmt.Printf("  ❌ FAIL [organizations-authority setup]: unexpected error: %v\n", err)
		fail++
	} else {
		_, err = client3.AcquireTokenByCredential(ctx, []string{"https://graph.microsoft.com/.default"},
			confidential.WithMtlsProofOfPossession())
		check("non-tenanted-authority(/organizations)", "mTLS PoP requires a tenanted authority", err)
	}

	// Error case 4: secret credential (not cert-based)
	secretCred, err := confidential.NewCredFromSecret("dummy-secret")
	if err != nil {
		fmt.Printf("  ❌ FAIL [secret-cred setup]: unexpected error: %v\n", err)
		fail++
	} else {
		client4, err := confidential.New(authority, cID, secretCred,
			confidential.WithAzureRegion(region))
		if err != nil {
			fmt.Printf("  ❌ FAIL [secret-cred client setup]: unexpected error: %v\n", err)
			fail++
		} else {
			_, err = client4.AcquireTokenByCredential(ctx, []string{"https://graph.microsoft.com/.default"},
				confidential.WithMtlsProofOfPossession())
			check("secret-credential", "mTLS requires a certificate credential", err)
		}
	}

	fmt.Printf("\n  Error cases: %d passed, %d failed\n", pass, fail)
}

func testHappyPath(cred confidential.Credential, certPEM, keyPEM []byte, tenantID, clientID, region, resource string) {
	ctx := context.Background()
	authority := "https://login.microsoftonline.com/" + tenantID
	scopes := []string{strings.TrimRight(resource, "/") + "/.default"}

	client, err := confidential.New(authority, clientID, cred,
		confidential.WithAzureRegion(region))
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	fmt.Printf("  Acquiring mTLS PoP token (region=%s, scope=%s)...\n", region, scopes[0])
	result, err := client.AcquireTokenByCredential(ctx, scopes,
		confidential.WithMtlsProofOfPossession())
	if err != nil {
		log.Fatalf("acquire token: %v", err)
	}

	fmt.Println()
	if result.BindingCertificate != nil {
		fmt.Printf("  ✅ BindingCertificate: subject=%s, expires=%s\n",
			result.BindingCertificate.Subject.CommonName,
			result.BindingCertificate.NotAfter.Format("2006-01-02"))
	} else {
		fmt.Println("  ❌ BindingCertificate is nil — expected non-nil for mTLS PoP")
	}

	tokenLen := len(result.AccessToken)
	if tokenLen > 60 {
		tokenLen = 60
	}
	fmt.Printf("  Token (first 60 chars): %s...\n", result.AccessToken[:tokenLen])
	fmt.Printf("  Expires: %s\n", result.ExpiresOn)
	fmt.Printf("  Source: %v\n", result.Metadata.TokenSource)

	tokenType, cnf := jwtutil.DecodeClaims(result.AccessToken)
	fmt.Printf("  token_type (JWT): %s\n", tokenType)
	fmt.Printf("  cnf claim (JWT):  %s\n", cnf)
	if tokenType == "mtls_pop" {
		fmt.Println("  ✅ Token type is mtls_pop")
	} else {
		fmt.Printf("  ⚠️  Token type is %q (expected mtls_pop — verify tenant has mtlsauth enabled)\n", tokenType)
	}

	// Second call — should hit cache
	fmt.Println("\n  Acquiring again (expect cache hit)...")
	result2, err := client.AcquireTokenByCredential(ctx, scopes,
		confidential.WithMtlsProofOfPossession())
	if err != nil {
		log.Fatalf("second acquire: %v", err)
	}
	if result2.Metadata.TokenSource == 1 { // TokenSourceCache
		fmt.Println("  ✅ Second call returned cached token")
	} else {
		fmt.Println("  ⚠️  Second call did NOT return cached token")
	}
	if result2.AccessToken == result.AccessToken {
		fmt.Println("  ✅ Same access token returned from cache")
	}

	// Downstream call — present the binding cert over mTLS
	fmt.Printf("\n  Making downstream call to %s...\n", resource)
	makeDownstreamCall(result.AccessToken, certPEM, keyPEM, resource)

	fmt.Println("\n  Happy path complete ✅")
}

// makeDownstreamCall makes an HTTPS request to resource, presenting the mTLS binding
// certificate in the TLS handshake and the mTLS PoP token in the Authorization header.
//
// The call target is GET {resource}/v1.0/organization for Graph, or GET {resource} for
// other resources. A 4xx response from the server (e.g. 403 Forbidden due to missing
// permissions) is still a success from the mTLS/token perspective — it means the TLS
// handshake and token authentication both succeeded.
func makeDownstreamCall(token string, certPEM, keyPEM []byte, resource string) {
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		fmt.Printf("  ❌ Build TLS cert: %v\n", err)
		return
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		},
	}
	httpClient := &http.Client{Transport: transport}

	// For Graph, append /v1.0/organization (requires Directory.Read.All or similar)
	url := strings.TrimRight(resource, "/")
	if strings.Contains(url, "graph.microsoft.com") {
		url += "/v1.0/organization"
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("  ❌ Build request: %v\n", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("  ❌ Downstream call failed (TLS/network error): %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	switch {
	case resp.StatusCode == 200:
		fmt.Printf("  ✅ Downstream call succeeded: HTTP %d\n", resp.StatusCode)
		fmt.Printf("     Response (first 200 chars): %.200s\n", string(body))
	case resp.StatusCode == 401:
		fmt.Printf("  ❌ Downstream call returned HTTP 401 — token or mTLS cert rejected\n")
		fmt.Printf("     Body: %.300s\n", string(body))
	case resp.StatusCode == 403:
		fmt.Printf("  ⚠️  Downstream call returned HTTP 403 — TLS handshake OK, token accepted, but missing permissions\n")
		fmt.Printf("     Body: %.300s\n", string(body))
	default:
		fmt.Printf("  ⚠️  Downstream call returned HTTP %d\n", resp.StatusCode)
		fmt.Printf("     Body: %.300s\n", string(body))
	}
}



