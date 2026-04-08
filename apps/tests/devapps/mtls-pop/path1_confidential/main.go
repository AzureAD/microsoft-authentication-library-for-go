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
// Cert files (test-cert.pem, test-key.pem) should be in the parent directory.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

func main() {
	tenantID := flag.String("tenant", "", "Azure AD tenant ID")
	clientID := flag.String("client", "", "Azure AD application (client) ID")
	region := flag.String("region", "centraluseuap", "Azure region for mTLS endpoint (e.g. westus2)")
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
	testHappyPath(cred, *tenantID, *clientID, *region)
}

func testErrorCases(cred confidential.Credential, tenantID, clientID, region string) {
	ctx := context.Background()
	// Use a real tenanted authority (tenant from IMDS)
	authority := "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47"
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

func testHappyPath(cred confidential.Credential, tenantID, clientID, region string) {
	ctx := context.Background()
	authority := "https://login.microsoftonline.com/" + tenantID
	scopes := []string{"https://graph.microsoft.com/.default"}

	client, err := confidential.New(authority, clientID, cred,
		confidential.WithAzureRegion(region))
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	fmt.Printf("  Acquiring mTLS PoP token (region=%s)...\n", region)
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

	tokenType, cnf := decodeJWTClaims(result.AccessToken)
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

	fmt.Println("\n  Happy path complete ✅")
}

// decodeJWTClaims decodes the JWT payload and returns (token_type, cnf) claims.
func decodeJWTClaims(token string) (tokenType, cnf string) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "(not a JWT)", ""
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "(decode error)", ""
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(data, &claims); err != nil {
		return "(json error)", ""
	}
	if tt, ok := claims["token_type"].(string); ok {
		tokenType = tt
	} else {
		tokenType = "(not present)"
	}
	if c, ok := claims["cnf"]; ok {
		b, _ := json.Marshal(c)
		cnf = string(b)
	} else {
		cnf = "(not present)"
	}
	return
}
