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

## Why `WithMtlsProofOfPossession()` is mandatory

It is not an optimization; it is the only flow a non-exportable key can use.

Every other confidential-client flow signs a `client_assertion` JWT, and the JWT RSA signing methods
require an `*rsa.PrivateKey`, which a KeyGuard key can never be. Those flows fail fast in
`Credential.JWT()` with:

```
this credential's private key is not exportable and can only be used with WithMtlsProofOfPossession()
```

With mTLS proof-of-possession no assertion is sent at all: the client certificate on the mutual-TLS
handshake both authenticates the client and binds the token, so the key is only ever asked to sign
the handshake.

## Provisioning a KeyGuard key

You need a Windows host with virtualization-based security enabled, and a certificate in a store
whose private key was created or imported with virtual isolation:

- **Import an existing PFX** with `PFXImportCertStore` and the `PKCS12_VIRTUAL_ISOLATION_KEY` flag.
  `Import-PfxCertificate` does not expose this flag, so the import has to go through the API.
- **Generate a new key** with `NCryptCreatePersistedKey` and `NCRYPT_USE_VIRTUAL_ISOLATION_FLAG`
  (`0x00020000`), then certify it.

Background: [Advancing key protection in Windows using
VBS](https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-key-protection-in-windows-using-vbs/4050988).

To confirm a certificate is actually KeyGuard protected, run the sample: it prints
`VBS isolated: true` only when CNG reports the isolation property. A software key prints
`VBS isolated: false` together with a warning.

## Registering the certificate

The app registration must have the certificate registered, and for mTLS proof-of-possession both the
application and the target resource have to be allow-listed by Entra. The sample requests a
Microsoft Graph scope and calls the Graph **mTLS** host by default; `graph.microsoft.com` does not
perform a client-certificate handshake, so a bound token has to go to the dedicated mTLS host.

## Running the sample

```powershell
go run ./apps/tests/devapps/keyguard `
  -thumbprint 0123456789ABCDEF0123456789ABCDEF01234567 `
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
$env:KEYGUARD_E2E_THUMBPRINT = "0123456789ABCDEF0123456789ABCDEF01234567"
go test -tags e2e -run KeyGuard -v ./apps/tests/e2e/...
```

`KEYGUARD_E2E_STORE_LOCATION`, `KEYGUARD_E2E_STORE_NAME`, `KEYGUARD_E2E_CLIENT_ID` and
`KEYGUARD_E2E_AUTHORITY` override the defaults, which point at the same SN/I lab app the mtls_pop
integration tests use.

## Troubleshooting

| Symptom                                                                       | Cause                                                                                       |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `certificate ... not found`                                                   | Wrong store location, store name, or thumbprint. `LocalMachine` also needs an elevated process. |
| `CryptAcquireCertificatePrivateKey failed`                                    | The certificate has no CNG private key, or this account cannot reach it.                     |
| `VBS isolated: false`                                                          | The key is a software key. Re-provision it with virtual isolation.                            |
| `chain length: 1` with a warning                                              | The intermediates are not installed locally and could not be fetched.                        |
| `not exportable and can only be used with WithMtlsProofOfPossession()`        | A flow other than mTLS PoP was requested. See above.                                          |
| HTTP 401 from the resource                                                     | The binding certificate was not presented, or the app/resource pair is not allow-listed.      |
