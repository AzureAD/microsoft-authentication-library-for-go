# mTLS PoP Manual Testing Guide

## Prerequisites

- Go 1.21+
- Access to an Azure subscription
- For Path 1 (SNI): An SNI certificate from OneCert, DSMS, or a test CA
- For Path 2 (MI): An Azure VM with system-assigned managed identity, Windows OS, VBS enabled

---

## Path 1 — Confidential Client (SNI Certificate)

### Step 1: Obtain a Test Certificate

A pre-generated public certificate (`test-cert.pem`) is checked into the repo at
`apps/tests/devapps/mtls-pop/test-cert.pem`. **The private key (`test-key.pem`) is
gitignored** — you must generate it locally.

Run this once to regenerate both files:

```bash
# From the repo root (requires OpenSSL or Git Bash on Windows)
openssl req -x509 -newkey rsa:2048 \
  -keyout apps/tests/devapps/mtls-pop/test-key.pem \
  -out apps/tests/devapps/mtls-pop/test-cert.pem \
  -days 365 -nodes -subj "/CN=msal-go-mtls-test"
```

Or on Windows with PowerShell (no OpenSSL required):
```powershell
$cert = New-SelfSignedCertificate `
    -Subject "CN=msal-go-mtls-test" `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -NotAfter (Get-Date).AddYears(1) `
    -CertStoreLocation "Cert:\CurrentUser\My"

# Export public cert (PEM) — safe to commit
$certB64 = [Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks')
"-----BEGIN CERTIFICATE-----`n$certB64`n-----END CERTIFICATE-----" |
    Out-File -Encoding ascii apps\tests\devapps\mtls-pop\test-cert.pem

# Export private key as PFX then convert (or use the PFX directly)
Export-PfxCertificate -Cert $cert `
    -FilePath apps\tests\devapps\mtls-pop\test-mtls.pfx `
    -Password (ConvertTo-SecureString "test" -AsPlainText -Force)
```

> If you regenerate the cert you must re-upload `test-cert.pem` to your Azure AD app registration.

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
    certs, key, err := confidential.CertFromPEM(append(certPEM, keyPEM...), "")
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

    fmt.Println("Token (first 50 chars):", result.AccessToken[:50])
    fmt.Println("BindingCertificate subject:", result.BindingCertificate.Subject.CommonName)
    fmt.Println("Expires:", result.ExpiresOn)
    fmt.Println("TokenSource:", result.Metadata.TokenSource) // 0=network, 1=cache
    
    // The token is of type mtls_pop — confirm via the cnf claim in the JWT payload.
    // AuthResult does not expose a TokenType field; check result.BindingCertificate != nil
    // to confirm an mTLS PoP token was returned.
    if result.BindingCertificate == nil {
        log.Fatal("expected BindingCertificate to be set for mTLS PoP tokens")
    }
    
    _ = tlsCert // Use tlsCert to make downstream calls (see Making Downstream Calls section)
}
```

### Step 4: Verify Expected Behavior

✅ `result.BindingCertificate != nil` — the cert bound to the token  
✅ `result.BindingCertificate.Subject.CommonName` matches the client ID in the app registration  
✅ Token is cached: a second call returns `result.Metadata.TokenSource == 1` (Cache) without a network request  
✅ Different certificates produce different cache entries  
✅ JWT payload contains `"cnf": { "x5t#S256": "<thumbprint>" }` matching the binding cert  

### Step 5: Validate Error Cases

```go
// Should fail: missing region
client2, _ := confidential.New(authority, clientID, cred) // no WithAzureRegion
_, err = client2.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
// Expected: error containing "mTLS PoP requires an Azure region"

// Should fail: non-tenanted authority
client3, _ := confidential.New("https://login.microsoftonline.com/common", clientID, cred,
    confidential.WithAzureRegion("westus2"))
_, err = client3.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
// Expected: error containing "mTLS PoP requires a tenanted authority"

// Should fail: secret credential
secretCred, _ := confidential.NewCredFromSecret("my-secret")
client4, _ := confidential.New(authority, clientID, secretCred, confidential.WithAzureRegion("westus2"))
_, err = client4.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
// Expected: error containing "mTLS requires a certificate credential"
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

1. Create a **Trusted Launch** Azure VM (Windows Server 2019 or later):
   - Enable **Secure Boot** and **vTPM** in the Security Type settings
   - Verify attestation capability after provisioning: `tpmtool.exe getdeviceinformation` → `Is Capable For Attestation: True`
2. Enable **system-assigned managed identity** in the VM's Identity blade
3. Grant the managed identity an Azure RBAC role on the target resource (e.g., Storage Blob Data Reader)
4. Enable **Credential Guard / VBS KeyGuard Key Isolation** inside the VM (see sub-steps below)

> **Important:** A standard VM (without Trusted Launch / Secure Boot + vTPM) cannot use VBS KeyGuard keys and will fail with `"mTLS PoP requires a VBS KeyGuard-protected RSA key"`. The VM's vTPM must have an EK certificate provisioned by the Azure platform.

#### Enable Credential Guard (VBS Key Isolation) inside the VM

After deploying a Trusted Launch VM, run the following in an elevated PowerShell session **inside the VM**, then reboot:

```powershell
# Enable Virtualization-Based Security + Credential Guard
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    -Name "RequirePlatformSecurityFeatures" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LsaCfgFlags" -Value 1 -Type DWord -Force  # 1 = enabled with UEFI lock

Restart-Computer -Force
```

After reboot, verify:
```powershell
# Credential Guard is active if lsaiso.exe is running:
Get-Process lsaiso -ErrorAction SilentlyContinue

# msinfo32 (GUI): "Virtualization-based security" must show "Running"
# and "Virtualization-based security services running" must include "Credential Guard"
msinfo32.exe
```

If `NCryptFinalizeKey` still returns `NTE_BAD_FLAGS (0x80090009)` after Credential Guard is enabled:
- The VM SKU may not support nested virtualization. Try a **Ddsv5-series** or **Esv5-series** VM.
- Ensure the VM generation is **Gen 2** (required for Trusted Launch).

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
        "https://graph.microsoft.com", // or https://storage.azure.com
        // Note: https://management.azure.com may return AADSTS392196 if not enrolled for mTLS PoP
        managedidentity.WithMtlsProofOfPossession(),
    )
    if err != nil {
        log.Fatal("acquire token:", err)
    }

    fmt.Println("BindingCertificate subject:", result.BindingCertificate.Subject.CommonName)
    fmt.Println("BindingCertificate expires:", result.BindingCertificate.NotAfter)
    fmt.Println("Token expires:", result.ExpiresOn)
    fmt.Println("TokenSource:", result.Metadata.TokenSource) // 0=network, 1=cache

    // Acquire again — should hit in-memory cert cache + token cache
    result2, err := client.AcquireToken(
        context.Background(),
        "https://graph.microsoft.com",
        managedidentity.WithMtlsProofOfPossession(),
    )
    if err != nil {
        log.Fatal("second acquire:", err)
    }
    if result2.Metadata.TokenSource == 1 {
        fmt.Println("✅ Token cache working")
    }
}
```

### Step 4: Verify Expected Behavior

✅ `result.BindingCertificate != nil` (IMDS-issued cert from `managedidentitysnissuer.login.microsoft.com`)  
✅ `result.BindingCertificate.Subject.CommonName` matches the VM's managed identity client ID  
✅ Second call: `result.Metadata.TokenSource == 1` (Cache) — no IMDS roundtrip  
✅ CNG key `MSALMtlsKey_{cuID}` visible in key storage: `certutil -csp "Microsoft Software Key Storage Provider" -key`  
✅ JWT payload contains `"cnf": { "x5t#S256": "<thumbprint>" }` matching the binding cert  
✅ JWT payload contains `"xms_tbflags": 2` (mTLS binding enforced) and `"appidacr": "2"` (cert auth)  
✅ Downstream mTLS call to `graph.microsoft.com` returns `401 Unauthorized` — this is **expected and correct**; the `401` means the TLS handshake and token were accepted; the managed identity simply has no Graph role assigned

### Step 5: Common Failure Scenarios

**"mTLS PoP requires a VBS KeyGuard-protected RSA key (got: Hardware)"** or **"...got: InMemory"**
- `NCryptFinalizeKey` rejected the VBS Virtual Isolation flags — VBS/Credential Guard is not enabled
- Verify: `msinfo32.exe` → "Virtualization-based security" must show "Running" and include "Credential Guard"
- Fix: Follow the Credential Guard setup steps above, then reboot

**"AttestKeyGuardImportKey failed ... Is Capable For Attestation must be true"**
- The VM is not a Trusted Launch VM, or vTPM was not provisioned with an EK certificate
- Verify: `tpmtool.exe getdeviceinformation` → `Is Capable For Attestation: True`
- Fix: Re-deploy the VM as a Trusted Launch VM with Secure Boot + vTPM enabled at creation time

**"IMDSv2 platform metadata missing client_id or tenant_id"**
- The VM's managed identity may not be configured correctly
- Verify with: `curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/getplatformmetadata?cred-api-version=2.0"`

**"GetOrCreateManagedIdentityKey: NCryptOpenStorageProvider failed"** (or similar KSP error)
- VBS/KeyGuard not available on this VM SKU
- Check with `msinfo32.exe`: Virtualization-based security must show "Running"
- Try a VM SKU that supports nested virtualization (e.g., Ddsv5-series)

**"issue credential returned status 403"**
- The VM's managed identity does not have permission for IMDSv2 credential issuance
- Contact your Azure subscription administrator

**AADSTS392196 from the token endpoint**
- The target resource (`scope=.../.default`) is not enrolled for mTLS PoP on this tenant
- Switch to `https://graph.microsoft.com` or `https://storage.azure.com` for testing
- `https://management.azure.com` is not enrolled in all tenants

**Error on non-Windows:**
```
mTLS PoP Managed Identity requires Windows with VBS KeyGuard support
```
This is expected. IMDSv2 with CNG KeyGuard requires Windows.

### Step 6: Make a Downstream mTLS Call

`AuthResult.BindingTLSCertificate` contains the complete TLS credential (public cert + CNG private key) needed to present the binding cert in a downstream mTLS call:

```go
import (
    "crypto/tls"
    "fmt"
    "net/http"
)

// result.BindingTLSCertificate holds the cert + CNG-backed private key as a tls.Certificate
transport := &http.Transport{
    TLSClientConfig: &tls.Config{
        Certificates: []tls.Certificate{*result.BindingTLSCertificate},
    },
}
httpClient := &http.Client{Transport: transport}

// Call a resource enrolled for mTLS PoP (graph.microsoft.com is confirmed enrolled)
req, _ := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/servicePrincipals?$top=1", nil)
req.Header.Set("Authorization", "mtls_pop "+result.AccessToken)
resp, err := httpClient.Do(req)
if err != nil {
    log.Fatal("downstream call:", err)
}
defer resp.Body.Close()
fmt.Println("Downstream HTTP status:", resp.Status)
// Expected: 200 OK — a 4xx from the API still means TLS + auth succeeded
```

> **Note:** `BindingTLSCertificate` is only set when `WithMtlsProofOfPossession()` is used. The private key is the CNG KeyGuard-backed RSA key created during the IMDSv2 flow and is never exported from the secure enclave.

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
- `"cnf": { "x5t#S256": "<thumbprint>" }` — certificate thumbprint bound to the token
- `"appidacr": "2"` — indicates certificate-based authentication
- `"xms_tbflags": 2` — indicates mTLS binding is enforced

> **Note:** The `token_type` claim is NOT present in the JWT payload. The `mtls_pop` type comes from the HTTP response `token_type` field. Use `result.BindingCertificate != nil` to confirm an mTLS PoP token was returned.

---

## Tracing mTLS Connections

To verify the mTLS handshake is occurring, use Wireshark or mitmproxy with TLS inspection:

```bash
# Use SSLKEYLOGFILE to capture TLS secrets (Go supports this)
SSLKEYLOGFILE=./tls-keys.log go run main.go
# Then open the pcap in Wireshark and apply the key log file
```

A successful mTLS handshake will show the client presenting its certificate in the `Certificate` TLS message during the handshake.
