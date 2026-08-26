# KeyGuard / CNG sample

This sample acquires an mTLS proof-of-possession token with a **non-exportable Windows key** and
uses it to call a protected resource. It is the Go counterpart of the SN/I mTLS PoP scenarios MSAL
.NET covers for VBS-protected certificates.

The key never leaves CNG. It is never exported, never converted to an `*rsa.PrivateKey`, and it is
used only to sign TLS handshakes — the one to Entra that MSAL performs, and the one to the resource
that the application performs.

```
public API -> developer code -> real credential -> token acquisition
  -> returned binding certificate -> resource call
```

## What is in this directory

| Path                  | What it is                                                                   |
| --------------------- | ---------------------------------------------------------------------------- |
| `ncryptsigner/`       | An importable `crypto.Signer` over a CNG key in a Windows certificate store.  |
| `main.go`             | The runnable sample. Copy this shape into your own application.               |

`ncryptsigner` is a normal (non-`main`) package so that both this sample and the end-to-end test in
`apps/tests/e2e/keyguard_mtls_e2e_test.go` can import it instead of duplicating ~300 lines of
P/Invoke.

Everything here is Windows-only (`//go:build windows`) and is **sample and test code**. MSAL Go adds
no public API for KeyGuard: `confidential.NewCredFromTLSCertificate` accepts any `crypto.Signer`, so
the platform-specific part belongs to the application. Copy `ncryptsigner` into your own project and
adapt it; do not treat it as a supported API.

## Why the application has to check isolation itself

`ncryptsigner.Signer.IsVirtualIsolated()` reads the CNG `"Virtual Iso"` property, which is `1` for a
KeyGuard key.

MSAL cannot make this check for you. It sets its internal signer-only flag purely from the Go *type*
of the key, so it cannot tell a VBS-isolated key from a software key wrapped in a `crypto.Signer`,
and it deliberately makes no isolation claim either way. A provisioning step that silently fell back
to a software key would therefore be completely invisible from Go. If isolation is a security
requirement for your workload, assert on it in your own code, as the sample does.

## Choosing between mTLS PoP and a client assertion

A non-exportable key works in both flows, so this is a design decision rather than a constraint.

**mTLS proof-of-possession**, which is what `main.go` does, sends no assertion at all: the client
certificate on the mutual-TLS handshake both authenticates the client and binds the token, so the key
is only ever asked to sign the handshake. The result is a certificate-bound token — a resource can
confirm the caller holds the key the token was issued to by comparing the presented certificate with
the `cnf["x5t#S256"]` claim. Request it with `confidential.WithMtlsProofOfPossession()`.

**A client assertion**, which is what every other confidential-client flow sends, is signed through
the `crypto.Signer` rather than an `*rsa.PrivateKey`, so the CNG handle signs it without exporting
anything. The result is an ordinary bearer token, not bound to the certificate. Add
`confidential.WithX5C()` when the app registration is SN/I, so Entra matches the assertion on the
certificate chain rather than on a per-certificate thumbprint.

Prefer proof-of-possession where the resource accepts it: a bound token is of no use to anyone who
steals it. Use an assertion when the resource only takes bearer tokens.

### Assertion signing can fall back to RS256

Assertions are signed PS256 (RSA-PSS) and carry an `x5t#S256` header thumbprint. Some providers —
CNG, KeyGuard, HSMs, smart cards — cannot do RSA-PSS at all, so if the signer fails MSAL rebuilds the
assertion once with PKCS #1 v1.5 (RS256) and an `x5t` thumbprint, as MSAL .NET does. It is automatic
and needs no configuration; the retry is visible only as a different `alg` on the wire.

Only signer-backed keys reach the retry. An exportable `*rsa.PrivateKey` uses Go's software RSA, which
always supports PSS, and ADFS and dSTS authorities sign RS256 to begin with, so both report the
original signing error instead.

## Provisioning a KeyGuard key

You need a Windows host with virtualization-based security enabled.

**Isolation can only be applied when a key is imported.** There is no way to create an isolated key
directly — `New-SelfSignedCertificate` has no isolation parameter, and `Import-PfxCertificate` has
no flag for it either. Every route below therefore ends in an import that sets
`PKCS12_VIRTUAL_ISOLATION_KEY`.

### If you already have a PFX

Import it with the Certificate Import Wizard (double-click the `.pfx`, or `certmgr.msc` →
*All Tasks* → *Import*) and tick the option to protect the private key with virtualization-based
security — labelled roughly *"Protect private key using virtualization-based security
(Non-exportable)"*; the exact wording varies by Windows build. Leave *"Mark this key as
exportable"* unchecked.

### If you want to make your own test certificate

A self-signed certificate is enough to exercise this sample's certificate handling and the TLS
handshake. It is **not** enough to acquire a token — for that the certificate has to be registered
on an app registration (see below).

```powershell
# 1. Create it. The key must be Exportable at this stage, purely so it can be
#    moved into a PFX in step 2. This is a temporary, non-isolated key.
$c = New-SelfSignedCertificate -Subject 'CN=my-keyguard-test' `
       -CertStoreLocation 'Cert:\CurrentUser\My' `
       -KeyAlgorithm RSA -KeyLength 2048 `
       -Provider 'Microsoft Software Key Storage Provider' `
       -KeyExportPolicy Exportable

# 2. Export to a PFX.
$pw = Read-Host -AsSecureString 'PFX password'
Export-PfxCertificate -Cert "Cert:\CurrentUser\My\$($c.Thumbprint)" `
                      -FilePath .\test.pfx -Password $pw

# 3. DELETE the exportable copy before re-importing. Do not skip this.
Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Thumbprint -eq $c.Thumbprint } | Remove-Item

# 4. Re-import test.pfx through the wizard with the virtualization-based
#    security option ticked (see above).

# 5. Verify - see the next section.
```

Step 3 matters. You deliberately created a **plaintext-exportable** private key in order to produce
a PFX. If you re-import over the top without removing it first, an exportable copy of the key can be
left behind in your store while you believe you are testing a non-exportable one. Delete the PFX
afterwards too.

### Getting the SHA-256 thumbprint

This sample identifies a certificate by its **SHA-256** thumbprint, because SHA-1 is collision-prone
and a lookup key that can collide is a certificate-substitution risk. Windows makes that value
slightly awkward to obtain: `$cert.Thumbprint`, certmgr's *Thumbprint* field, and the paths in the
`Cert:` drive are all SHA-1, and certmgr has no SHA-256 column. Ask for it explicitly:

```powershell
# By subject, when only one certificate matches:
(Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq 'CN=my-keyguard-test' }).GetCertHashString('SHA256')

# Or convert a SHA-1 thumbprint you already have. The Cert: drive is indexed by SHA-1, so the
# SHA-1 value is still what addresses the certificate here:
(Get-Item Cert:\CurrentUser\My\<sha1 thumbprint>).GetCertHashString('SHA256')
```

Keep that 64-character value: it is what `-thumbprint` and `KEYGUARD_THUMBPRINT` expect. Passing the
40-character SHA-1 value instead is the most likely mistake, so the sample detects it and tells you
how to convert it rather than reporting a bare length error.

### Verifying isolation

This check is offline and needs no app registration, so do it before anything else:

```powershell
$c   = Get-ChildItem Cert:\CurrentUser\My |
       Where-Object { $_.GetCertHashString('SHA256') -eq '<sha256 thumbprint>' }
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)
$rsa.Key.ExportPolicy   # expect: None
$rsa.Key.GetProperty('Virtual Iso',
    [System.Security.Cryptography.CngPropertyOptions]::None).GetValue()[0]   # expect: 1
```

`Virtual Iso` is `1` for a KeyGuard key and `0` for a software key. A freshly created
`New-SelfSignedCertificate` key reports `0`, which is the quickest way to confirm the check is
telling you something real.

Running this sample reports the same thing via CNG: `VBS isolated: true`, or
`VBS isolated: false` plus a warning for a software key. Prefer the check above when you are only
validating provisioning — it does not need a tenant, a client id, or network access.

### Automating it (build agents)

A headless build agent cannot use the wizard. Call `PFXImportCertStore` directly with
`PKCS12_VIRTUAL_ISOLATION_KEY | PKCS12_ALWAYS_CNG_KSP | PKCS12_INCLUDE_EXTENDED_PROPERTIES`, and
deliberately **omit** `CRYPT_EXPORTABLE`. Under `LocalMachine\My` the agent's service account also
needs an ACL granting it read access to the private key, or `CryptAcquireCertificatePrivateKey`
will fail.

Background: [Advancing key protection in Windows using
VBS](https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-key-protection-in-windows-using-vbs/4050988).

## Registering the certificate

The app registration must have the certificate registered, and for mTLS proof-of-possession both the
application and the target resource have to be allow-listed by Entra. The sample requests a
Microsoft Graph scope and calls the Graph **mTLS** host by default; `graph.microsoft.com` does not
perform a client-certificate handshake, so a bound token has to go to the dedicated mTLS host.

## Running the sample

```powershell
go run ./apps/tests/devapps/keyguard `
  -thumbprint 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF `
  -client-id  <app registration client id> `
  -authority  https://login.microsoftonline.com/<tenant id>
```

Every flag can also be supplied through the environment: `KEYGUARD_THUMBPRINT`,
`KEYGUARD_STORE_LOCATION` (default `CurrentUser`), `KEYGUARD_STORE_NAME` (default `My`),
`KEYGUARD_CLIENT_ID`, `KEYGUARD_AUTHORITY`, `KEYGUARD_SCOPE`, and `KEYGUARD_RESOURCE_URL`. Pass
`-resource ""` to acquire a token without calling a resource.

Expected output:

```
== certificate ==
store       : CurrentUser\My
subject     : CN=LabAuth.MSIDLab.com
issuer      : CN=CCME G1 TLS RSA 2048 SHA256 2049 WCUS CA 01
not after   : 2026-12-11T17:42:26Z
VBS isolated: true
chain length: 2
  [0] leaf         CN=LabAuth.MSIDLab.com
  [1] intermediate CN=CCME G1 TLS RSA 2048 SHA256 2049 WCUS CA 01

== token ==
token type  : mtls_pop
token source: IdentityProvider
expires on  : 2026-08-25T14:27:46-04:00
binding x5t#S256: pbQwciWT23GvZqHUS5SM9Tms5GHD7w8JxDeRmHV6Nlc

== resource ==
url         : https://mtlstb.graph.microsoft.com/v1.0/applications?$top=1
status      : 200 OK
the resource accepted the certificate-bound token
```

`chain length` is worth watching. `ncryptsigner` builds the chain with `CertGetCertificateChain`, so
it carries the leaf plus any intermediates; a self-signed root is dropped because `x5c`
conventionally omits it and Entra does not need it. A `chain length: 1` plus a `WARNING` line means
chain building degraded to leaf-only and `x5c` will carry no intermediates.

## Running the end-to-end test

The same flow is asserted by `apps/tests/e2e/keyguard_mtls_e2e_test.go`, which additionally checks
the token's `cnf["x5t#S256"]` claim and the negative case where the bound token is presented without
the client certificate. It is behind the `e2e` build tag and skips unless a thumbprint is supplied:

```powershell
$env:KEYGUARD_E2E_THUMBPRINT = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
go test -tags e2e -run KeyGuard -v ./apps/tests/e2e/...
```

`KEYGUARD_E2E_STORE_LOCATION`, `KEYGUARD_E2E_STORE_NAME`, `KEYGUARD_E2E_CLIENT_ID` and
`KEYGUARD_E2E_AUTHORITY` override the defaults, which point at the same SN/I lab app the mtls_pop
integration tests use.

## Troubleshooting

| Symptom                                                                       | Cause                                                                                       |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `certificate ... not found`                                                   | Wrong store location, store name, or SHA-256 thumbprint. `LocalMachine` also needs an elevated process. |
| `looks like a SHA-1 thumbprint`                                               | A 40-character SHA-1 value was passed; the lookup needs the 64-character SHA-256 one. See above. |
| `CryptAcquireCertificatePrivateKey failed`                                    | The certificate has no CNG private key, or this account cannot reach it.                     |
| `VBS isolated: false`                                                          | The key is a software key. Re-provision it with virtual isolation.                            |
| `chain length: 1` with a warning                                              | The intermediates are not installed locally and could not be fetched.                        |
| HTTP 401 from the resource                                                     | The binding certificate was not presented, or the app/resource pair is not allow-listed.      |
