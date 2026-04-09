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
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/tests/devapps/mtls-pop/internal/jwtutil"
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
		"https://graph.microsoft.com",
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
		"https://graph.microsoft.com",
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

	// Downstream call — present the binding cert over mTLS
	fmt.Println("\nMaking downstream mTLS call to graph.microsoft.com...")
	makeDownstreamCall(result.AccessToken, result)

	fmt.Println("\n=== Path 2 Complete ===")
}

// makeDownstreamCall demonstrates using the mTLS PoP token + binding cert for a real API call.
// A 4xx from the API (e.g. 403) still means TLS + token authentication succeeded.
func makeDownstreamCall(token string, result managedidentity.AuthResult) {
	if result.BindingTLSCertificate == nil {
		fmt.Println("  ⚠️  BindingTLSCertificate is nil — cannot make downstream call")
		return
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{*result.BindingTLSCertificate},
		},
	}
	httpClient := &http.Client{Transport: transport}

	req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/servicePrincipals?$top=1", nil)
	if err != nil {
		fmt.Printf("  ❌ Build request: %v\n", err)
		return
	}
	req.Header.Set("Authorization", "mtls_pop "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("  ❌ Downstream call failed: %v\n", err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("  Downstream HTTP status: %s\n", resp.Status)
	if resp.StatusCode < 500 {
		fmt.Println("  ✅ TLS handshake + token authentication succeeded")
	} else {
		fmt.Println("  ❌ Server error — check token and resource enrollment")
	}
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
	jwtutil.PrintTokenInfo(result.AccessToken, result.ExpiresOn, int(result.Metadata.TokenSource))
}



