// mTLS PoP Manual Test — Path 2: Managed Identity (IMDSv2, Windows + VBS)
//
// Tests the managed identity mTLS PoP flow end-to-end on an Azure VM with:
//   - System-assigned managed identity
//   - Windows OS with VBS (Virtualization-Based Security) KeyGuard
//   - IMDSv2 endpoint accessible at 169.254.169.254
//
// Usage:
//   go run .
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

func main() {
	fmt.Println("=== Path 2: Managed Identity mTLS PoP ===")
	fmt.Println()

	ctx := context.Background()

	client, err := managedidentity.New(managedidentity.SystemAssigned())
	if err != nil {
		log.Fatalf("create MI client: %v", err)
	}

	fmt.Println("Acquiring mTLS PoP token via IMDSv2...")
	result, err := client.AcquireToken(
		ctx,
		"https://management.azure.com",
		managedidentity.WithMtlsProofOfPossession(),
	)
	if err != nil {
		log.Fatalf("acquire token: %v\n\nCommon causes:\n"+
			"  - VBS/KeyGuard not running (check msinfo32.exe)\n"+
			"  - IMDSv2 not returning platform metadata\n"+
			"  - VM managed identity not configured\n"+
			"  - 403 from IMDS issuecredential endpoint", err)
	}

	fmt.Println()
	printResult("First call (from IMDS)", result)

	// Second call — should hit in-memory cert + token cache
	fmt.Println("\nAcquiring again (expect cache hit)...")
	result2, err := client.AcquireToken(
		ctx,
		"https://management.azure.com",
		managedidentity.WithMtlsProofOfPossession(),
	)
	if err != nil {
		log.Fatalf("second acquire: %v", err)
	}
	printResult("Second call (should be cached)", result2)

	if result2.AccessToken == result.AccessToken {
		fmt.Println("\n✅ Token cache working: same token returned on second call")
	} else {
		fmt.Println("\n⚠️  Different token on second call — may indicate cache miss or token was expiring")
	}

	if result2.Metadata.TokenSource == 1 {
		fmt.Println("✅ TokenSource == Cache")
	} else {
		fmt.Println("⚠️  TokenSource != Cache (got fresh token)")
	}

	fmt.Println("\n=== Path 2 Complete ===")
}

func printResult(label string, result managedidentity.AuthResult) {
	fmt.Printf("[%s]\n", label)
	if result.BindingCertificate != nil {
		fmt.Printf("  ✅ BindingCertificate:\n")
		fmt.Printf("     Subject:    %s\n", result.BindingCertificate.Subject.CommonName)
		fmt.Printf("     Issuer:     %s\n", result.BindingCertificate.Issuer.CommonName)
		fmt.Printf("     NotBefore:  %s\n", result.BindingCertificate.NotBefore.Format("2006-01-02 15:04:05 UTC"))
		fmt.Printf("     NotAfter:   %s\n", result.BindingCertificate.NotAfter.Format("2006-01-02 15:04:05 UTC"))
	} else {
		fmt.Println("  ❌ BindingCertificate is nil — expected non-nil for mTLS PoP")
	}

	tokenLen := len(result.AccessToken)
	if tokenLen > 60 {
		tokenLen = 60
	}
	fmt.Printf("  Token (first 60 chars): %s...\n", result.AccessToken[:tokenLen])
	fmt.Printf("  Expires:     %s\n", result.ExpiresOn)
	fmt.Printf("  TokenSource: %v\n", result.Metadata.TokenSource)

	tokenType, cnf := decodeJWTClaims(result.AccessToken)
	fmt.Printf("  token_type (JWT): %s\n", tokenType)
	fmt.Printf("  cnf claim (JWT):  %s\n", cnf)

	if tokenType == "mtls_pop" {
		fmt.Println("  ✅ Token type is mtls_pop")
	} else {
		fmt.Printf("  ⚠️  Token type is %q (expected mtls_pop)\n", tokenType)
	}
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
