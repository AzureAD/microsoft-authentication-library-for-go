# mTLS PoP Manual Testing Guide

## Prerequisites

- Go 1.21+
- Access to an Azure subscription
- For Path 1 (SNI): An SNI certificate from OneCert, DSMS, or a test CA
- For Path 2 (MI): An Azure VM with system-assigned managed identity, Windows OS, VBS enabled

---

## Path 1 — Confidential Client (SNI Certificate)

### Step 1: Obtain a Test Certificate

For local testing, generate a self-signed certificate:

```powershell
# Generate a self-signed cert for testing (PowerShell)
$cert = New-SelfSignedCertificate `
    -Subject "CN=msal-go-mtls-test" `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -NotAfter (Get-Date).AddYears(1) `
    -CertStoreLocation "Cert:\CurrentUser\My"

# Export to PFX
Export-PfxCertificate -Cert $cert -FilePath test-mtls.pfx -Password (ConvertTo-SecureString "test" -AsPlainText -Force)
```

Or use OpenSSL:
```bash
openssl req -x509 -newkey rsa:2048 -keyout test-key.pem -out test-cert.pem \
  -days 365 -nodes -subj "/CN=msal-go-mtls-test"
```

### Step 2: Register Your App in Azure AD

1. Register an application in [Azure Portal → App Registrations](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps)
2. Note the **Application (client) ID** and **Directory (tenant) ID**
3. Upload the certificate's public key under **Certificates & secrets**
4. Grant the application an API permission (e.g., `https://graph.microsoft.com/.default`)

> **Note:** mTLS PoP token acquisition requires the tenant to have `mtlsauth` endpoints enabled. Contact your Azure AD administrator or use a tenant where this is available.

### Step 3: Write the Test Code

```go
package main

import (
    "context"
    "crypto/tls"
    "fmt"
    "log"
    "os"

    "github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
    "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

func main() {
    // Load certificate
    certPEM, _ := os.ReadFile("test-cert.pem")
    keyPEM, _ := os.ReadFile("test-key.pem")
    tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
    if err != nil {
        log.Fatal("load cert:", err)
    }

    // Create MSAL credential
    certs, key, err := confidential.CertFromPEM(certPEM, keyPEM)
    if err != nil {
        log.Fatal("parse cert:", err)
    }
    cred, err := confidential.NewCredFromCert(certs, key)
    if err != nil {
        log.Fatal("create cred:", err)
    }

    // Create client with region
    client, err := confidential.New(
        "https://login.microsoftonline.com/{YOUR_TENANT_ID}",
        "{YOUR_CLIENT_ID}",
        cred,
        confidential.WithAzureRegion("westus2"), // use your VM's region
    )
    if err != nil {
        log.Fatal("create client:", err)
    }

    // Acquire mTLS PoP token
    result, err := client.AcquireTokenByCredential(
        context.Background(),
        []string{"https://graph.microsoft.com/.default"},
        confidential.WithMtlsProofOfPossession(),
    )
    if err != nil {
        log.Fatal("acquire token:", err)
    }

    fmt.Println("Token type:", result.TokenType)
    fmt.Println("Token (first 50 chars):", result.AccessToken[:50])
    fmt.Println("BindingCertificate subject:", result.BindingCertificate.Subject.CommonName)
    fmt.Println("Expires:", result.ExpiresOn)
    
    // Verify token type
    if result.TokenType != "mtls_pop" {
        log.Fatal("expected mtls_pop token type, got:", result.TokenType)
    }
    
    _ = tlsCert // Use tlsCert to make downstream calls (see Making Downstream Calls section)
}
```

### Step 4: Verify Expected Behavior

✅ `result.TokenType == "mtls_pop"`  
✅ `result.BindingCertificate` is not nil and matches the certificate you provided  
✅ Token is cached: a second call returns the same token without a network request  
✅ Different certificates produce different cache entries  

### Step 5: Validate Error Cases

```go
// Should fail: missing region
client2, _ := confidential.New(authority, clientID, cred) // no WithAzureRegion
_, err = client2.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
// Expected: error containing "mtls_pop_no_region"

// Should fail: non-tenanted authority
client3, _ := confidential.New("https://login.microsoftonline.com/common", clientID, cred,
    confidential.WithAzureRegion("westus2"))
_, err = client3.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
// Expected: error containing "mtls_pop_requires_tenanted_authority"

// Should fail: secret credential
secretCred, _ := confidential.NewCredFromSecret("my-secret")
client4, _ := confidential.New(authority, clientID, secretCred, confidential.WithAzureRegion("westus2"))
_, err = client4.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
// Expected: error containing "mtls_pop_no_cert"
```

### Step 6: Make a Downstream mTLS Call

```go
import (
    "crypto/tls"
    "net/http"
)

// Build HTTP client with the binding certificate
transport := &http.Transport{
    TLSClientConfig: &tls.Config{
        Certificates: []tls.Certificate{tlsCert},
    },
}
httpClient := &http.Client{Transport: transport}

req, _ := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
req.Header.Set("Authorization", "mtls_pop "+result.AccessToken)
resp, err := httpClient.Do(req)
```

---

## Path 2 — Managed Identity (IMDSv2, Windows Only)

### Step 1: Provision the Azure VM

1. Create an Azure VM (Windows Server 2019 or later for VBS support)
2. Enable **system-assigned managed identity** in the VM's Identity blade
3. Grant the managed identity an Azure RBAC role on the target resource (e.g., Storage Blob Data Reader)
4. Ensure VBS (Virtualization-Based Security) is enabled:
   - Azure VM SKUs with nested virtualization support VBS (e.g., `Standard_D2s_v5`)
   - Verify in Device Manager or `msinfo32.exe` → Virtualization-based security: Running

### Step 2: Install Go and the Application

On the VM:
```powershell
winget install GoLang.Go
# or download from https://go.dev/dl/
```

### Step 3: Write the Test Code

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

func main() {
    client, err := managedidentity.New(managedidentity.SystemAssigned())
    if err != nil {
        log.Fatal("create client:", err)
    }

    result, err := client.AcquireToken(
        context.Background(),
        "https://storage.azure.com",
        managedidentity.WithMtlsProofOfPossession(),
    )
    if err != nil {
        log.Fatal("acquire token:", err)
    }

    fmt.Println("Token type:", result.TokenType)
    fmt.Println("BindingCertificate subject:", result.BindingCertificate.Subject.CommonName)
    fmt.Println("BindingCertificate expires:", result.BindingCertificate.NotAfter)
    fmt.Println("Token expires:", result.ExpiresOn)
}
```

### Step 4: Verify Expected Behavior

✅ `result.TokenType == "mtls_pop"`  
✅ `result.BindingCertificate` is not nil (IMDS-issued cert)  
✅ `result.BindingCertificate.Subject.CommonName` matches the VM's client ID  
✅ Second call returns cached cert + token (no IMDS roundtrip)  
✅ CNG key `MSALMtlsKey_{cuID}` visible in key storage (check with `certutil -csp "Microsoft Platform Crypto Provider" -key`)  

### Step 5: Common Failure Scenarios

**"IMDSv2 platform metadata missing client_id or tenant_id"**
- The VM's managed identity may not be configured correctly
- Verify with: `curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/getplatformmetadata?cred-api-version=2.0"`

**"GetOrCreateKeyGuardKey: NCryptOpenStorageProvider failed"**
- VBS/KeyGuard not available on this VM SKU
- Check with `msinfo32.exe`: Virtualization-based security must show "Running"
- Try a VM SKU that supports nested virtualization (e.g., Ddsv5-series)

**"issue credential returned status 403"**
- The VM's managed identity does not have permission for IMDSv2 credential issuance
- Contact your Azure subscription administrator

**Error on non-Windows:**
```
mTLS PoP Managed Identity requires Windows with VBS KeyGuard support
```
This is expected. IMDSv2 with CNG KeyGuard requires Windows.

---

## Auto-Region Detection Testing

Test that region auto-detection works inside an Azure VM:

```go
import "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"

client, err := confidential.New(
    "https://login.microsoftonline.com/{tenantID}",
    clientID,
    cred,
    confidential.WithAzureRegion(authority.AutoDetectRegion),
)
```

Expected: msal-go queries `http://169.254.169.254/metadata/instance?api-version=2021-02-01`, parses `compute.location`, and uses it as the region.

Verify by checking the token endpoint used (enable debug logging or use a proxy like Fiddler/mitmproxy).

---

## Comparing Tokens

To inspect a token, decode the JWT payload (second segment, Base64URL):

```bash
# Linux/Mac
echo -n "<token>" | cut -d. -f2 | base64 -d | python3 -m json.tool

# PowerShell
$parts = "<token>" -split "\."
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($parts[1].PadRight($parts[1].Length + (4 - $parts[1].Length % 4) % 4, '='))) | ConvertFrom-Json
```

For mTLS PoP tokens, look for:
- `"cnf": { "x5t#S256": "<thumbprint>" }` — certificate thumbprint claim
- `"token_type": "mtls_pop"` or check the response header

---

## Tracing mTLS Connections

To verify the mTLS handshake is occurring, use Wireshark or mitmproxy with TLS inspection:

```bash
# Use SSLKEYLOGFILE to capture TLS secrets (Go supports this)
SSLKEYLOGFILE=./tls-keys.log go run main.go
# Then open the pcap in Wireshark and apply the key log file
```

A successful mTLS handshake will show the client presenting its certificate in the `Certificate` TLS message during the handshake.
