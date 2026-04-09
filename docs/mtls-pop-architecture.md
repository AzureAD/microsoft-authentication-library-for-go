# mTLS PoP Architecture — Deep Dive

This document describes the internal architecture of the mTLS Proof of Possession implementation in msal-go, how it achieves parity with msal-dotnet, and the technical decisions made along the way. For the user-facing API guide, see [mtls-pop.md](mtls-pop.md).

---

## 1. Go-to-Windows-CNG Without CGo

Go has no built-in C FFI (like Python's `ctypes` or Java's JNI). The standard approach for calling native Windows DLLs from Go is `syscall.NewLazyDLL` / `NewProc` — no CGo compilation, no C headers, no build toolchain beyond the Go compiler.

```go
var (
    ncrypt                        = syscall.NewLazyDLL("ncrypt.dll")
    procNCryptOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
    procNCryptCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
    procNCryptSetProperty         = ncrypt.NewProc("NCryptSetProperty")
    procNCryptFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
    procNCryptSignHash             = ncrypt.NewProc("NCryptSignHash")
    procNCryptExportKey           = ncrypt.NewProc("NCryptExportKey")
    procNCryptFreeObject          = ncrypt.NewProc("NCryptFreeObject")
    procNCryptDeleteKey           = ncrypt.NewProc("NCryptDeleteKey")
)
```

### Comparison to Other Languages

| Language / Library | CNG Mechanism | Notes |
|---|---|---|
| **msal-go** | `syscall.NewLazyDLL` → `Proc.Call(...)` | No CGo; pure Go + unsafe.Pointer |
| **msal-dotnet** | P/Invoke (`[DllImport("ncrypt.dll")]`) | C# managed/unmanaged interop |
| **msal-node** | .NET subprocess (`MsalMtlsMsiHelper.exe`) | No native CNG access; delegates to .NET |

Files affected: `apps/managedidentity/cng_windows.go` (Windows only, `//go:build windows`).

### Struct Marshalling

There is no automatic struct marshalling — Go `unsafe.Pointer` is used to pass C-compatible structs. For example, `BCRYPT_PSS_PADDING_INFO`:

```go
type bcryptPSSPaddingInfo struct {
    pszAlgId *uint16   // UTF-16LE string pointer (CNG uses wide strings)
    cbSalt   uint32
}
```

All CNG wide-string parameters use `syscall.UTF16PtrFromString`. All ANSI strings (for `AttestationClientLib.dll`) use `syscall.BytePtrFromString`.

---

## 2. `cngSigner`: Wrapping a CNG Key Handle as `crypto.Signer`

The Go standard library's `crypto.Signer` interface is the bridge between Windows CNG and Go's TLS stack:

```go
type Signer interface {
    Public() PublicKey
    Sign(rand io.Reader, digest []byte, opts SignerOpts) ([]byte, error)
}
```

msal-go implements this with `cngSigner`:

```go
type cngSigner struct {
    hKey   uintptr      // CNG NCRYPT_KEY_HANDLE — opaque handle to the key in KSP
    pubKey *rsa.PublicKey
}
```

### Why This Works with `crypto/tls`

Go's `crypto/tls` package needs to sign TLS handshake data. It accepts any `crypto.PrivateKey` that is also a `crypto.Signer` — it **never** requires an `*rsa.PrivateKey` with raw key bytes. The TLS stack calls `signer.Sign(rand, digest, opts)` and gets back a signature. The private key bytes never cross any boundary.

This is the same reason Go's TLS stack works with hardware tokens (PKCS#11), YubiKeys, or any HSM-backed key — as long as it implements `crypto.Signer`.

### PSS vs PKCS1v15 Dispatch

The CSR signing step requires RSASSA-PSS; TLS client auth typically uses PKCS1v15 or PSS depending on the negotiated cipher suite. `cngSigner.Sign` dispatches on the `opts` type:

```go
func (s *cngSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
    if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
        return s.signPSS(digest, pssOpts)
    }
    return s.signPKCS1v15(digest, opts)
}
```

Both paths call `NCryptSignHash` with the appropriate `BCRYPT_*_PADDING_INFO` struct and padding flag (`NCRYPT_PAD_PSS_FLAG = 0x8` or `NCRYPT_PAD_PKCS1_FLAG = 0x2`).

`NCryptSignHash` is called twice: once with a null output buffer to query the required signature length, then again to produce the actual signature. This is the standard CNG two-phase pattern.

---

## 3. Key Creation: 3-Level Fallback (Mirrors MSAL.NET)

msal-go mirrors the `WindowsManagedIdentityKeyProvider` from msal-dotnet with three priority tiers:

```
GetOrCreateManagedIdentityKey(keyName)
  │
  ├─ 1. KeyGuard  (Software KSP + USER scope + VBS flags)
  │      NCryptCreatePersistedKey flags: NCRYPT_OVERWRITE_KEY_FLAG
  │                                    | NCRYPT_USE_VIRTUAL_ISOLATION_FLAG
  │                                    | NCRYPT_USE_PER_BOOT_KEY_FLAG
  │      Verify: NCryptGetProperty("Virtual Iso") != 0
  │      → returns keyTypeKeyGuard
  │
  ├─ 2. Hardware  (Software KSP + USER scope, no VBS flags)
  │      Key name: "{keyName}_hw" (distinct from KeyGuard key name)
  │      → returns keyTypeHardware
  │
  └─ 3. InMemory  (rsa.GenerateKey in process memory, ephemeral)
         → returns keyTypeInMemory
```

### Key Properties (All Tiers)

| Property | Value | msal-dotnet Equivalent |
|---|---|---|
| Provider | `Microsoft Software Key Storage Provider` | `CngProvider.MicrosoftSoftwareKeyStorageProvider` |
| Scope | USER (no `NCRYPT_MACHINE_KEY_FLAG`) | `CngKeyCreationOptions.None` |
| Algorithm | RSA 2048-bit | RSA 2048 |
| Export policy | `NCRYPT_ALLOW_EXPORT_NONE` (0) | `CngExportPolicies.None` |
| Key name | `MSALMtlsKey_{cuID}` / `MSALMtlsKey_{cuID}_hw` | `MSALMtlsKey_{cuID}` |

**USER scope** (no machine flag) is critical. The original implementation used `NCRYPT_MACHINE_KEY_FLAG` (machine scope), which caused `NTE_BAD_FLAGS (0x80090009)` when trying to apply VBS flags — VBS key isolation only works in USER scope.

### VBS KeyGuard Verification

Creating a key with `NCRYPT_USE_VIRTUAL_ISOLATION_FLAG` is not sufficient to guarantee VBS protection — the flag might be silently ignored if Credential Guard is not active. The code verifies using `NCryptGetProperty("Virtual Iso")`:

```go
func isKeyGuardProtected(hKey uintptr) bool {
    propName, _ := syscall.UTF16PtrFromString("Virtual Iso")
    var value uint32
    var bytesUsed uint32
    ret, _, _ := procNCryptGetProperty.Call(hKey, ...)
    return ret == 0 && bytesUsed >= 4 && value != 0
}
```

If the key was created but is not VBS-protected, it is **deleted and recreated once** (mirrors MSAL.NET's recreate-and-revalidate logic) before falling back to Hardware tier.

### Security Implications of Each Tier

| Tier | Private key location | Survives reboot? | mTLS PoP supported? |
|---|---|---|---|
| KeyGuard | VBS secure enclave (Credential Guard) | No (`PER_BOOT_KEY_FLAG`) | ✅ |
| Hardware | Software KSP in user profile | Yes | ❌ (no attestation possible) |
| InMemory | Process heap | No | ❌ |

Only KeyGuard keys can proceed to attestation and token acquisition. Hardware/InMemory keys trigger an error with a precise message about needing a Trusted Launch VM.

---

## 4. `AttestationClientLib.dll`: Interop and Distribution

### What the DLL Does

`AttestationClientLib.dll` is a native Windows library from the KeyGuard team that contacts the **Microsoft Azure Attestation (MAA)** service and produces a JWT proving that a given CNG key handle is VBS KeyGuard-protected. This JWT is sent to IMDS as `attestation_token` in the `/issuecredential` request.

### How msal-dotnet Distributes It

msal-dotnet uses a dedicated NuGet package — **`Microsoft.Azure.Security.KeyGuardAttestation`** — referenced by `Microsoft.Identity.Client.KeyAttestation.csproj`. The DLL is bundled as a native runtime asset at `runtimes/win-x64/native/AttestationClientLib.dll` and is automatically deployed to the output folder when the NuGet package is restored. Users only need `dotnet add package Microsoft.Identity.Client.KeyAttestation`.

### How msal-go Handles It (Known Difference)

Go has no equivalent of NuGet native assets. msal-go loads the DLL at runtime:

```go
attestClientLib = syscall.NewLazyDLL("AttestationClientLib.dll")
```

Windows searches for the DLL in the standard load order: application directory first, then System32, then PATH.

**Users must obtain and deploy the DLL manually:**
1. Install the .NET NuGet package: `dotnet add package Microsoft.Azure.Security.KeyGuardAttestation --version <latest>`
2. The DLL will appear at: `%USERPROFILE%\.nuget\packages\microsoft.azure.security.keyguardattestation\<version>\runtimes\win-x64\native\AttestationClientLib.dll`
3. Copy it to the same directory as the msal-go application binary.

### Why msal-go Cannot Bundle the DLL Automatically

msal-dotnet's zero-touch distribution works because NuGet has a first-class **native asset pipeline**:

- The NuGet package places the DLL under `runtimes/win-x64/native/` inside the package.
- When a .NET project is built or published, MSBuild automatically resolves that path and copies the DLL to the project's output directory alongside the `.exe`.
- The developer only runs `dotnet add package` — the DLL placement is invisible.

Go modules have no equivalent mechanism:

- A Go module is **source files only**. `go get` and `go mod download` retrieve `.go` files; there is no convention or tooling for bundling binary artifacts in a module.
- Even if a `.dll` were committed into the module's repository (under, say, `_native/`), there is no build pipeline step that would automatically copy it to the user's output directory.
- CGo does not help here. CGo links C libraries at **compile time** (static or shared link). `AttestationClientLib.dll` is a **runtime** dynamic dependency, loaded on-demand via `LoadLibrary`/`NewLazyDLL`. Even with CGo, the DLL would still need to be present at runtime alongside the binary.

In practice this is low-friction: Path 2 only runs on Trusted Launch Azure VMs with Credential Guard enabled — environments where the deployment pipeline is already controlled and placing one additional file is straightforward.

### Interop Pattern

The function signatures are reverse-engineered from msal-dotnet's `AttestationInterop.cs` / `AttestationClientLib.cs`:

```go
// C signatures:
//   int  InitAttestationLib(AttestationLogInfo*)
//   int  AttestKeyGuardImportKey(char* endpoint, char* authToken, char* clientPayload,
//                                NCRYPT_KEY_HANDLE keyHandle, char** token, char* clientId)
//   void FreeAttestationToken(char* token)
//   void UninitAttestationLib()

var (
    procInitAttestationLib      = attestClientLib.NewProc("InitAttestationLib")
    procAttestKeyGuardImportKey = attestClientLib.NewProc("AttestKeyGuardImportKey")
    procFreeAttestationToken    = attestClientLib.NewProc("FreeAttestationToken")
    procUninitAttestationLib    = attestClientLib.NewProc("UninitAttestationLib")
)
```

All strings are ANSI (not wide) — `syscall.BytePtrFromString` is used (not `UTF16PtrFromString`). The `logInfo` struct contains a function pointer for logging; msal-go passes a no-op callback because the DLL requires a non-null log function:

```go
var dummyLogCallback = syscall.NewCallback(func(ctx, tag uintptr, lvl uint32, fn uintptr, line uint32, msg uintptr) uintptr {
    return 0
})
```

The `maybeAttest` helper only invokes the DLL for KeyGuard keys — the DLL is never loaded for Hardware or InMemory keys. If the DLL is absent and a KeyGuard key was created (which requires Credential Guard — only available on Trusted Launch VMs where the DLL should also be present), the `LazyProc.Call` will return a descriptive error.

---

## 5. CSR Format: Manual `encoding/asn1`

### Why `x509.CreateCertificateRequest` Cannot Be Used

Go's `x509.CreateCertificateRequest` has two limitations that make it unsuitable:

1. **No RSASSA-PSS support.** It only supports PKCS1v15 (RSA) and ECDSA. IMDS requires PSS with SHA-256.
2. **No custom attributes.** PKCS#10 has an `attributes [0]` field for application-specific extensions. Go's function has no mechanism to inject arbitrary ASN.1 attributes. IMDS requires an attribute carrying the VM's compute unit identifier (cuID) under a proprietary Microsoft OID.

### The Solution: `encoding/asn1`

Go's `encoding/asn1` package provides low-level DER serialization. The `generateCSR` function hand-builds every field of the PKCS#10 structure to match MSAL.NET's `Csr.Generate()` exactly:

#### Subject DN

```go
dcOID := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25} // domainComponent
subject := pkix.Name{
    CommonName: clientID,
    ExtraNames: []pkix.AttributeTypeAndValue{
        {Type: dcOID, Value: tenantID},
    },
}
subjectDER, _ := asn1.Marshal(subject.ToRDNSequence())
// Result: SEQUENCE { SET { SEQUENCE { OID=CN, UTF8 clientID } }
//                    SET { SEQUENCE { OID=DC, UTF8 tenantID } } }
```

#### SubjectPublicKeyInfo

```go
pubKeyDER, _ := x509.MarshalPKIXPublicKey(key.Public())
var spki asn1.RawValue
asn1.Unmarshal(pubKeyDER, &spki) // re-embed as raw DER
```

#### cuID Attribute

The cuID attribute carries a JSON blob identifying the VM compute unit, wrapped in a proprietary OID:

```go
// OID 1.3.6.1.4.1.311.90.2.10
// Structure: SEQUENCE { OID, SET { UTF8String(json) } }
// Wrapped in: attributes [0] IMPLICIT { SEQUENCE { OID, SET { UTF8 } } }
```

This is assembled by `buildCuIDAttribute()` using successive `asn1.Marshal` calls.

#### Signature: RSASSA-PSS

The `CertificationRequestInfo` SEQUENCE is hashed with SHA-256, then signed via `cngSigner.Sign`:

```go
h := crypto.SHA256.New()
h.Write(certReqInfo)
digest := h.Sum(nil)
sig, _ := key.Sign(rand.Reader, digest, &rsa.PSSOptions{
    SaltLength: rsa.PSSSaltLengthEqualsHash, // salt = 32 bytes (SHA-256 output)
    Hash:       crypto.SHA256,
})
```

The signature algorithm identifier is the full RSASSA-PSS OID (`1.2.840.113549.1.1.10`) with explicit SHA-256 hash, MGF1-SHA-256, and salt length parameters. This cannot be expressed with Go's standard `x509` package and must be assembled manually.

---

## 6. Binding Certificate Cache

The IMDS-issued binding certificate is short-lived (typically 14 days) but expensive to obtain (requires key creation + attestation + IMDS round trip). msal-go caches it in-memory:

```
globalMtlsCertCache (process-global, *mtlsCertCache)
    cache: map[string]*mtlsBindingInfo   // key = cuID
    mu: sync.RWMutex
```

Each cache entry (`mtlsBindingInfo`) stores:

| Field | Type | Purpose |
|---|---|---|
| `tlsCert` | `tls.Certificate` | Complete cert + CNG signer (for downstream TLS) |
| `x509Cert` | `*x509.Certificate` | Parsed cert (for inspection / `BindingCertificate`) |
| `endpoint` | `string` | mTLS token endpoint from IMDS |
| `clientID` | `string` | VM managed identity client ID |
| `tenantID` | `string` | VM tenant ID |
| `expiresAt` | `time.Time` | `cert.NotAfter` minus 5 minutes (pre-expiry buffer) |

### Concurrency: Double-Checked Locking

```
Read lock → check expiry → if valid, return
    ↓ (not valid)
Write lock → check expiry again (another goroutine may have refreshed) → if still invalid
    → call factory (IMDS) → store result → return
```

The 5-minute buffer ensures smooth operation during certificate rotation. When the cached cert expires, the next call triggers a full refresh: new key lookup/creation, attestation, and IMDS credential issuance.

---

## 7. SHA1 vs SHA256 Thumbprint: Parity with msal-dotnet

When building a JWT assertion for the token endpoint (Path 1), the certificate thumbprint is included in the JWT header. The hash algorithm depends on the identity provider:

| Identity Provider | JWT Signing Alg | Thumbprint Hash | JWT Header Key |
|---|---|---|---|
| Entra ID / AAD / B2C / CIAM | PS256 | SHA-256 | `x5t#S256` |
| ADFS / DSTS | RS256 | **SHA-1** | `x5t` |

### Why SHA-1 for ADFS/DSTS

[RFC 7517 §4.8](https://tools.ietf.org/html/rfc7517#section-4.8) defines `x5t` as the base64url-encoded SHA-1 thumbprint of the DER-encoded certificate. ADFS and DSTS servers only accept `x5t` (SHA-1) — they do not recognize `x5t#S256`. This is not a security weakness in msal-go; SHA-256 (`x5t#S256`) is used for all modern identity providers.

### msal-dotnet Parity

msal-dotnet has the identical logic in `JsonWebToken.cs` and `AuthorityInfo.cs`:

```csharp
// AuthorityInfo.cs
internal bool IsSha2CredentialSupported =>
    AuthorityType != AuthorityType.Dsts &&
    AuthorityType != AuthorityType.Generic &&
    AuthorityType != AuthorityType.Adfs;

// JsonWebToken.cs
string alg = useSha2AndPss ? "PS256" : "RS256";
string thumbprintKey = useSha2AndPss ? "x5t#S256" : "x5t";
// ComputeCertThumbprint: SHA-256 when useSha2, SHA-1 otherwise
```

msal-go's equivalent (in `accesstokens.go`):

```go
isADFSorDSTS := authParams.AuthorityInfo.AuthorityType == authority.ADFS ||
    authParams.AuthorityInfo.AuthorityType == authority.DSTS

var signingMethod jwt.SigningMethod = jwt.SigningMethodPS256
thumbprintKey := "x5t#S256"

if isADFSorDSTS {
    signingMethod = jwt.SigningMethodRS256
    thumbprintKey = "x5t"
}
```

The `thumbprint()` function uses `sha1.Sum` for ADFS/DSTS and `sha256.Sum256` for everything else. The `/* #nosec */ //NOSONAR` comment on the SHA-1 line suppresses static analysis warnings — this usage is intentional and spec-required. msal-dotnet carries a similar `//codeql [SM03799] Backwards Compatibility` comment on its PKCS1 path.

---

## Summary: msal-go vs msal-dotnet Implementation Map

| Component | msal-dotnet | msal-go |
|---|---|---|
| CNG access | P/Invoke (`[DllImport("ncrypt.dll")]`) | `syscall.NewLazyDLL` + `Proc.Call` |
| Key type | `CngKey` (managed wrapper) | `cngSigner` (`uintptr` handle + `crypto.Signer`) |
| Key scope | USER (`CngKeyCreationOptions.None`) | USER (no `NCRYPT_MACHINE_KEY_FLAG`) |
| Key export policy | `CngExportPolicies.None` | `NCRYPT_ALLOW_EXPORT_NONE` (0) |
| Key fallback tiers | `WindowsManagedIdentityKeyProvider`: KeyGuard → Hardware → InMemory | `GetOrCreateManagedIdentityKey`: same 3 tiers |
| VBS check | `IsKeyGuardProtected()` via `CngKey.GetProperty("Virtual Iso")` | `isKeyGuardProtected(hKey)` via `NCryptGetProperty` |
| CSR generation | `Csr.Generate()` — custom `CertificateRequest` builder | `generateCSR()` — manual `encoding/asn1` |
| Attestation DLL | Bundled via `Microsoft.Azure.Security.KeyGuardAttestation` NuGet | Loaded via `syscall.NewLazyDLL`; must be placed manually |
| TLS handshake | Schannel (OS TLS) | `crypto/tls` (pure Go) |
| Subprocess needed? | No | No |
| SHA1/SHA256 thumbprint | `IsSha2CredentialSupported` → ADFS=SHA1, else SHA256 | `isADFSorDSTS` → same logic |
