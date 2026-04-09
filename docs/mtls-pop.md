# mTLS Proof of Possession (mTLS PoP) in msal-go

## Overview

mTLS Proof of Possession (RFC 8705) binds an access token to an X.509 certificate. The token is issued only after the client authenticates the TLS handshake with that certificate against a regional mTLS token endpoint (`{region}.mtlsauth.microsoft.com`). Downstream resource calls must present the same certificate over mTLS.

**Benefits over bearer tokens:**
- Token is cryptographically bound to the certificate — stolen tokens cannot be replayed on a different TLS connection.
- Satisfies enhanced proof-of-possession requirements for zero-trust architectures.
- Required by some Microsoft services for high-security scenarios.

**Spec:** [RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://www.rfc-editor.org/rfc/rfc8705)

---

## Why Go Uses the .NET Approach

Go's `crypto/tls` is a pure-Go TLS implementation that accepts any `crypto.PrivateKey` implementing `crypto.Signer` — including keys backed by Windows CNG (Cryptography Next Generation). This means:

| Library | TLS Stack | CNG Support | Approach |
|---------|-----------|-------------|----------|
| **msal-go** | `crypto/tls` (pure Go) | ✅ Via `crypto.Signer` | Direct cert use |
| **msal-dotnet** | Schannel (.NET) | ✅ Native | Direct cert use |
| **msal-node** | OpenSSL (Node.js) | ❌ None | .NET subprocess (`MsalMtlsMsiHelper.exe`) |

No subprocess is needed in msal-go.

---

## Two Implementation Paths

### Path 1 — Confidential Client (SNI Certificate)

The application has an SNI certificate (e.g., from OneCert/DSMS) and uses it as the client credential.

**Requirements:**
- Certificate-based credential (`NewCredFromCert`)
- Tenanted authority (not `/common` or `/organizations`)
- Azure region configured

**API:**

```go
// 1. Create credential from certificate
cred, err := confidential.NewCredFromCert(certChain, privateKey)

// 2. Create client — specify tenant ID in authority and Azure region
client, err := confidential.New(
    "https://login.microsoftonline.com/{tenantID}",
    "client-id",
    cred,
    confidential.WithAzureRegion("westus2"),  // or AutoDetectRegion()
)

// 3. Acquire mTLS PoP token
result, err := client.AcquireTokenByCredential(ctx, []string{"https://graph.microsoft.com/.default"},
    confidential.WithMtlsProofOfPossession(),
)

// result.BindingCertificate is the X.509 cert bound to this token —
// use it (with its private key) in the TLS handshake for downstream calls.
// result.Metadata.TokenSource == base.TokenSourceCache on subsequent calls.
```

**Token caching:** mTLS PoP tokens are cached separately from bearer tokens using the certificate's x5t#S256 thumbprint as part of the cache key.

**Why a region is required:** Path 1 sends the token request to a separate regional mTLS endpoint (`{region}.mtlsauth.microsoft.com`) rather than the standard `login.microsoftonline.com`. The mTLS TLS handshake — where the certificate authenticates the client — must terminate at a regional load balancer that can validate it. Without a region, there is no valid endpoint and msal-go returns an error.

| Cloud | Token Endpoint |
|-------|----------------|
| Public | `https://{region}.mtlsauth.microsoft.com/{tenantID}/oauth2/v2.0/token` |
| US Government | `https://{region}.mtlsauth.microsoftonline.us/{tenantID}/oauth2/v2.0/token` |
| China | `https://{region}.mtlsauth.partner.microsoftonline.cn/{tenantID}/oauth2/v2.0/token` |
| DSTS | Standard DSTS endpoint (no region required) |

Use `confidential.WithAzureRegion("westus2")` to specify a region explicitly, or `confidential.WithAzureRegion(authority.AutoDetectRegion)` to detect it automatically via IMDS (only works inside an Azure VM). The `REGION_NAME` environment variable is also respected.

> **Path 2 (Managed Identity)** does not require a region from the caller — IMDS returns the correct mTLS endpoint directly in the `/issuecredential` response.

---

### Path 2 — Managed Identity (IMDSv2)

On Azure VMs, the IMDS (Instance Metadata Service) v2 can issue a short-lived binding certificate. The key is generated in Windows CNG with VBS KeyGuard protection — the private key never leaves the hardware security boundary.

**Requirements:**
- Azure VM or VMSS with system-assigned managed identity
- IMDSv2 enabled (`cred-api-version=2.0`)
- Windows OS with VBS (Virtualization-Based Security) KeyGuard available
- **[Trusted Launch Azure VM](https://learn.microsoft.com/azure/virtual-machines/trusted-launch)** with Secure Boot + vTPM — `Is Capable For Attestation: True` (verify with `tpmtool.exe getdeviceinformation`)
- `AttestationClientLib.dll` present alongside the binary. This DLL is not bundled by msal-go (Go modules have no native asset distribution mechanism — see [architecture doc](mtls-pop-architecture.md#why-msal-go-cannot-bundle-the-dll-automatically) for the full explanation). To obtain it:
  1. Run: `dotnet add package Microsoft.Azure.Security.KeyGuardAttestation --version <latest>`
  2. Copy from: `%USERPROFILE%\.nuget\packages\microsoft.azure.security.keyguardattestation\<version>\runtimes\win-x64\native\AttestationClientLib.dll`
  3. Place it in the same directory as the msal-go application binary.
- `DefaultToIMDS` source (not Arc, AppService, CloudShell, etc.)

**API:**

```go
import "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"

client, err := managedidentity.New(managedidentity.SystemAssigned())

result, err := client.AcquireToken(ctx, "https://graph.microsoft.com",
    managedidentity.WithMtlsProofOfPossession(),
)

// result.BindingCertificate is the IMDS-issued cert bound to the token.
// result.BindingTLSCertificate is the complete tls.Certificate (cert + CNG key) —
// use it directly in tls.Config.Certificates for downstream mTLS calls.
// result.Metadata.TokenSource == base.TokenSourceCache on subsequent calls.
```

> **Resource note:** Not all Azure resources accept mTLS PoP tokens yet. Use `https://graph.microsoft.com` or `https://storage.azure.com` for testing. `https://management.azure.com` may return `AADSTS392196` if the resource is not enrolled.

**Non-Windows:** Returns an error (`mTLS PoP Managed Identity requires Windows with VBS KeyGuard support`).

---

## Bearer-over-mTLS (`WithSendCertificateOverMtls`)

If you want certificate authentication via the TLS handshake (instead of a JWT `client_assertion` in the request body) but do **not** need a PoP-bound token, use `WithSendCertificateOverMtls`:

```go
client, err := confidential.New(
    "https://login.microsoftonline.com/{tenantID}",
    "client-id",
    cred,
    confidential.WithSendCertificateOverMtls(),
)

// Acquires a bearer token, authenticated via mTLS handshake
result, err := client.AcquireTokenByCredential(ctx, scopes)
// result.TokenType == "Bearer"
```

**Behavior matrix:**

| `WithSendCertificateOverMtls` | `WithMtlsProofOfPossession()` | Transport | Token Type |
|---|---|---|---|
| false | No | JWT `client_assertion` in body | Bearer |
| true | No | mTLS handshake | Bearer |
| false | Yes | mTLS handshake | `mtls_pop` |
| true | Yes | mTLS handshake | `mtls_pop` |

---

## Making Downstream Calls with a PoP Token

After acquiring an mTLS PoP token, downstream resource calls must use the same certificate in their TLS connection:

### Path 1 — Confidential Client

Build a `tls.Certificate` from your certificate PEM and private key, then attach the token:

```go
tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)

transport := &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}}}
httpClient := &http.Client{Transport: transport}

req, _ := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/organization", nil)
req.Header.Set("Authorization", "mtls_pop "+result.AccessToken)
resp, err := httpClient.Do(req)
```

### Path 2 — Managed Identity

`AuthResult.BindingTLSCertificate` is populated automatically with the IMDS-issued cert and CNG private key. The private key never leaves the VBS KeyGuard secure enclave:

```go
transport := &http.Transport{
    TLSClientConfig: &tls.Config{
        Certificates: []tls.Certificate{*result.BindingTLSCertificate},
    },
}
httpClient := &http.Client{Transport: transport}

req, _ := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/servicePrincipals?$top=1", nil)
req.Header.Set("Authorization", "mtls_pop "+result.AccessToken)
resp, err := httpClient.Do(req)
// A 4xx response from the API (e.g. 401/403) still confirms TLS + token auth succeeded.
// 401 is expected if the managed identity has no Graph API role assigned.
```

---

## Token Caching

mTLS PoP tokens are cached separately from bearer tokens. The cache key includes the certificate's x5t#S256 thumbprint (SHA-256 of the DER-encoded certificate, Base64URL-encoded without padding). This ensures:

- Different certificates produce different cache entries.
- Bearer and mTLS PoP tokens for the same client/tenant don't collide.
- Token expiry is honored normally.

For IMDSv2 (Path 2), the binding certificate itself is cached in-memory with a 5-minute pre-expiry buffer to ensure smooth certificate rotation. The CNG key is persisted in the "Microsoft Software Key Storage Provider" under the name `MSALMtlsKey_{cuID}` (USER scope), where `cuID` is the VM's compute unit identifier from IMDS platform metadata.

---

## Error Reference

| Error Message | Condition | Resolution |
|--------------|-----------|-----------|
| `mTLS PoP requires an Azure region; use WithAzureRegion() or AutoDetectRegion()` | `WithMtlsProofOfPossession()` called without `WithAzureRegion()` | Add `WithAzureRegion("regionName")` or `WithAzureRegion(authority.AutoDetectRegion)` to the client |
| `mTLS requires a certificate credential; use NewCredFromCert` | mTLS PoP requested but credential is not certificate-based | Create the client with `NewCredFromCert()` |
| `mTLS PoP requires a tenanted authority; use a specific tenant ID in the authority URL` | Authority is `/common` or `/organizations` | Use a specific tenant ID: `https://login.microsoftonline.com/{tenantID}` |
| `mTLS PoP Managed Identity requires Windows with VBS KeyGuard support` | IMDSv2 path on non-Windows | Only supported on Windows with VBS |
| `mTLS PoP Managed Identity is only supported with IMDS` | MI source is not `DefaultToIMDS` | mTLS PoP MI requires IMDS source (standard Azure VM) |
| `IMDSv2 platform metadata missing...` | IMDS not available or VM identity not configured | Ensure the VM has system-assigned managed identity and IMDSv2 access |
| `AttestKeyGuardImportKey failed ... Is Capable For Attestation must be true` | VM vTPM not attestation-capable | Use a Trusted Launch Azure VM (Secure Boot + vTPM with EK certificate) |

> **Note:** The `apps/errors` package defines short code constants (e.g. `errors.MtlsPopNoRegion = "mtls_pop_no_region"`) for use in programmatic checks, but the error messages returned to callers use the plain-English strings in the table above. Always check `err.Error()` contains the plain-English substring, not the code constant.


