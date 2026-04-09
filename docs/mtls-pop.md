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

---

### Path 2 — Managed Identity (IMDSv2)

On Azure VMs, the IMDS (Instance Metadata Service) v2 can issue a short-lived binding certificate. The key is generated in Windows CNG with VBS KeyGuard protection — the private key never leaves the hardware security boundary.

**Requirements:**
- Azure VM or VMSS with system-assigned managed identity
- IMDSv2 enabled (`cred-api-version=2.0`)
- Windows OS with VBS (Virtualization-Based Security) KeyGuard available
- **[Trusted Launch Azure VM](https://learn.microsoft.com/azure/virtual-machines/trusted-launch)** with Secure Boot + vTPM — `Is Capable For Attestation: True` (verify with `tpmtool.exe getdeviceinformation`)
- `AttestationClientLib.dll` present at `C:\Windows\System32\` (standard on Azure Windows VMs)
- `DefaultToIMDS` source (not Arc, AppService, CloudShell, etc.)

**API:**

```go
import "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"

client, err := managedidentity.New(managedidentity.SystemAssigned())

result, err := client.AcquireToken(ctx, "https://graph.microsoft.com",
    managedidentity.WithMtlsProofOfPossession(),
)

// result.BindingCertificate is the IMDS-issued cert bound to the token.
// Use it (with the CNG-backed private key) in downstream mTLS connections.
// result.Metadata.TokenSource == base.TokenSourceCache on subsequent calls.
```

> **Resource note:** Not all Azure resources accept mTLS PoP tokens yet. Use `https://graph.microsoft.com` or `https://storage.azure.com` for testing. `https://management.azure.com` may return `AADSTS392196` if the resource is not enrolled.

**Non-Windows:** Returns an error (`mTLS PoP Managed Identity requires Windows with VBS KeyGuard support`).

---

## Regional mTLS Token Endpoints

mTLS PoP uses a separate regional token endpoint, not the standard `login.microsoftonline.com` endpoint:

| Cloud | Endpoint Pattern |
|-------|-----------------|
| Public | `https://{region}.mtlsauth.microsoft.com/{tenantID}/oauth2/v2.0/token` |
| US Government | `https://{region}.mtlsauth.microsoftonline.us/{tenantID}/oauth2/v2.0/token` |
| China | `https://{region}.mtlsauth.partner.microsoftonline.cn/{tenantID}/oauth2/v2.0/token` |
| DSTS | Standard DSTS token endpoint (no region required) |

The region must be an Azure region name (e.g., `westus2`, `eastus`, `northeurope`).

### Auto-Detecting the Region

```go
confidential.WithAzureRegion(authority.AutoDetectRegion)
```

When `AutoDetectRegion` is used, msal-go queries the IMDS instance metadata endpoint (`http://169.254.169.254/metadata/instance`) to determine the Azure region. The result is cached. This only works inside an Azure VM.

Alternatively, set the `REGION_NAME` environment variable.

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

```go
// Build TLS client using the binding certificate
tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
// or for CNG keys: construct tls.Certificate{Certificate: certDER, PrivateKey: cnfSigner}

tlsConfig := &tls.Config{Certificates: []tls.Certificate{tlsCert}}
transport := &http.Transport{TLSClientConfig: tlsConfig}
httpClient := &http.Client{Transport: transport}

req, _ := http.NewRequest("GET", "https://resource.example.com/api", nil)
req.Header.Set("Authorization", "mtls_pop " + result.AccessToken)
resp, err := httpClient.Do(req)
```

For Managed Identity (Path 2), use `result.BindingCertificate` (the `*x509.Certificate`) together with the CNG `crypto.Signer` returned by `GetOrCreateKeyGuardKey` — the private key stays in the VBS KeyGuard and is never exported.

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

---

## Comparison with Other MSAL Libraries

| Feature | msal-go | msal-dotnet | msal-node |
|---------|---------|-------------|-----------|
| SNI / CCA path | ✅ | ✅ | ✅ |
| Managed Identity (IMDSv2) | ✅ Windows | ✅ Windows | ✅ via subprocess |
| CNG KeyGuard support | ✅ Via `crypto.Signer` | ✅ Native | ❌ (subprocess handles it) |
| Non-Windows MI PoP | ❌ (returns error) | ❌ | ✅ (via subprocess) |
| Bearer-over-mTLS | ✅ | ✅ | ✅ |
| Auto-region detection | ✅ (`AutoDetectRegion`) | ✅ (`TryAutoDetect`) | ✅ |
| MAA attestation | ✅ Via `AttestationClientLib.dll` | ✅ | ✅ |

---

## Architecture Diagram

```
Confidential Client (SNI path):
  App ──[has cert+key]──► AcquireTokenByCredential(WithMtlsProofOfPossession())
                                        │
                              Build MtlsPopAuthenticationScheme(cert)
                              Resolve region (env var / IMDS / explicit)
                              Build mTLS endpoint URL
                                        │
                              POST {region}.mtlsauth.microsoft.com/{tenant}/token
                              (TLS handshake presents cert; no client_assertion JWT)
                                        │
                              token_type=mtls_pop token  ◄────────────────────────
                              result.BindingCertificate = cert used
                              result.Metadata.TokenSource = Cache on repeat calls

Managed Identity (IMDSv2 path):
  App ──► AcquireToken(resource, WithMtlsProofOfPossession())
                │
                ├── GET IMDS /metadata/identity/getplatformmetadata?cred-api-version=2.0
                │         → clientID, tenantID, cuID, attestationEndpoint
                │
                ├── CNG: GetOrCreateManagedIdentityKey("MSALMtlsKey_{cuID}")
                │         Priority: KeyGuard (VBS) > Hardware (Software KSP) > InMemory
                │         [RSA-2048, USER scope, non-exportable; KeyGuard requires Credential Guard]
                │
                ├── Build PKCS#10 CSR (manual ASN.1 — matches MSAL.NET Csr.Generate()):
                │         Subject:    CN={clientId}, DC={tenantId}
                │         Signature:  RSASSA-PSS SHA-256
                │         Attributes: OID 1.3.6.1.4.1.311.90.2.10 → UTF8String(JSON CuID)
                │
                ├── AttestationClientLib.dll: AttestKeyGuardImportKey(attestationEndpoint, key)
                │         → MAA JWT proving key is VBS KeyGuard-protected
                │         [Only for KeyGuard keys; requires Trusted Launch VM + attestation-capable vTPM]
                │
                ├── POST IMDS /metadata/identity/issuecredential
                │         body: { csr: <base64>, attestation_token: <MAA JWT> }
                │         → binding_certificate (base64 DER) + mtls_authentication_endpoint
                │         [Issued by managedidentitysnissuer.login.microsoft.com]
                │
                ├── Cache binding cert in-memory (expires 5 min before cert NotAfter)
                │
                └── POST {mtlsAuthEndpoint}/{tenantID}/oauth2/v2.0/token
                    grant_type=client_credentials, scope={resource}/.default, token_type=mtls_pop
                    (TLS handshake presents IMDS-issued binding cert)
                          │
                    token_type=mtls_pop token  ◄─────────────────────────────────
                    result.BindingCertificate = IMDS-issued cert
                    cnf.x5t#S256 in JWT = SHA-256 thumbprint of binding cert
                    result.Metadata.TokenSource = Cache on repeat calls
```
