# Managed identity over IMDSv2 — demo

A runnable demonstration of managed identity over IMDSv2: a managed identity access token that is
cryptographically bound to a certificate whose private key is isolated by Windows KeyGuard
(virtualization-based security), rather than a plain bearer token that anyone who obtains it can
replay.

## What it demonstrates

The opt-in is one per-call option:

```go
client, _ := managedidentity.New(managedidentity.SystemAssigned())
res, _ := client.AcquireToken(ctx, "https://vault.azure.net",
    managedidentity.WithMtlsProofOfPossession())
```

and the result carries everything needed to use the token:

| | |
|---|---|
| `res.Metadata.TokenType` | `"mtls_pop"`, not `"Bearer"` |
| `res.BindingCertificate` | the certificate chain plus the live private key |
| `res.BindingCertificateThumbprint()` | equals the token's `cnf["x5t#S256"]` claim |

Behind that one option MSAL makes three requests before Entra is ever reached: it asks IMDS for
platform metadata, mints a KeyGuard key and exchanges a CSR for a short-lived client certificate,
then uses that certificate to authenticate the mutual-TLS handshake to Entra. `-trace` shows the
last of those legs.

The demo verifies rather than asserts: it reads the `cnf` claim out of the token it received and
checks that it matches the thumbprint of the certificate MSAL handed back. If those two disagree,
the token is not bound and the program fails.

### It is useful on a host that cannot do any of this

Every failure mode of this feature is environmental — wrong OS, virtualization-based security off,
an IMDSv1-only host, a managed identity source with no credential endpoint, a missing native
library. So the demo reports host capabilities *before* it tries anything:

```
== host capabilities ==
  GOOS:                            windows
  Source:                          DefaultToIMDS
  MaxSupportedBindingStrength:     KeyGuard
  IsMtlsPoPSupportedByHost():      true
```

and when an acquisition does fail it names the cause, the fix, and the sentinel to match in code:

```
imdsv2: AcquireToken failed: managedidentity: WithAttestationSupport requires
WithMtlsProofOfPossession or WithRequestOverMtls

== what this means ==
  cause:    -attest only means something on a path that mints a binding key.
  fix:      Combine -attest with -mode pop or -mode bearer-mtls.

  Match this in code with errors.Is(err, managedidentity.ErrAttestationRequiresMtls).
```

Running this on a laptop or in a Linux container is therefore an informative outcome, not an opaque
error.

### Two things that are easy to get wrong when calling the resource

Both fail as a bare connection reset rather than as an error that can be read, which is why the
demo shows the working transport rather than describing it:

- **`GetClientCertificate` rather than `Certificates`.** Go filters `Certificates` against the
  certificate authorities the server advertises and silently sends nothing when none match.
  `GetClientCertificate` is not filtered.
- **TLS 1.2 with client renegotiation allowed.** A resource that enforces token binding is free to
  complete the handshake, read the request, see the `mtls_pop` scheme, and only *then* ask for the
  certificate by renegotiating. Go declines renegotiation by default, and `crypto/tls` does not
  implement post-handshake authentication, the TLS 1.3 equivalent.

## Running it

For PR validation, Azure Pipelines reports **MI E2E – IMDSv2** separately from
the legacy IMDS check. The IMDSv2 check runs the tagged `TestIMDSv2*` suite in
the same Windows lab used by MSAL .NET and fails if a required test is skipped
or missing. The commands below are for manual smoke testing, not the CI suite.

### Natural certificate renewal (manual E2E)

On the Windows lab VM, use a system-assigned identity with secret-read access
to the token-binding vault. Set `IMDSV2_E2E_VAULT` to its hostname and
`IMDSV2_E2E_SECRET` to the test secret name. Build from the repository root and
stage the x64 attestation DLL beside the test executable:

```powershell
go test -c -tags 'e2e,imdsv2soak' -o .\imdsv2-soak.test.exe .\apps\tests\e2e
Copy-Item 'C:\path\to\AttestationClientLib.dll' .\
.\imdsv2-soak.test.exe -test.v -test.count=1 -test.run '^TestSoakIMDSv2NaturalCertificateRenewal$' -test.timeout=168h
```

Keep the process and VM running. Use an isolated fixture and don't force-refresh,
reboot, clear the key or certificate store, or run other clients that can change
the binding state. The test reuses one MSAL client, reads the secret every five
minutes, and requires a different, longer-lived certificate and a successful
read when the original enters its 24-hour refresh window. It logs the expected
renewal time; increase the timeout if needed. The public-key fingerprint is
diagnostic only: certificate renewal does not require key rotation. This test
is excluded from PR CI by the `imdsv2soak` build tag. The experiment branch
`experiments/imdsv2-renewal` runs only the short `TestIMDSv2RenewalPreflight`
in addition to the regular suite. A green preflight confirms a working
baseline and records the refresh time; it does not prove renewal.

### Attestation prerequisites

Only callers that opt in with `WithAttestationSupport()`—the demo's `-attest` flag—need the **x64
Microsoft Visual C++ 2015–2022 Redistributable** ([latest supported downloads](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170)).
Developers deploy `AttestationClientLib.dll` beside the host executable or in `System32` and install
the runtime it depends on, including `MSVCP140.dll` and `VCRUNTIME140.dll`. If the DLL is present but
those dependencies are absent, MSAL reports a native-library load error. Ordinary IMDSv2 mTLS
without attestation does not require this prerequisite.

MSAL obtains and sends the attestation statement; the developer does not provide an attestation
token manually.

The binding key is per-boot. After Windows restarts, MSAL replaces an unusable persisted key,
including one that fails to open with `NTE_VBS_CANNOT_DECRYPT_KEY` (`0x8009003A`), then obtains
a certificate for the replacement. Other key-open errors, such as access denied, still fail
acquisition. Do not delete the shared key container or clear the certificate store to recover.

```sh
# What can this host do? No token is acquired.
go run ./apps/tests/devapps/imdsv2 -capabilities-only

# Acquire a certificate-bound token for the system-assigned identity.
go run ./apps/tests/devapps/imdsv2 -mode pop

# Acquire and then call a resource that enforces token binding.
go run ./apps/tests/devapps/imdsv2 -mode pop \
    -call "https://myvault.vault.azure.net/secrets?api-version=7.4"

# A user-assigned identity.
go run ./apps/tests/devapps/imdsv2 -id-type client -id <client-id>

# Watch the mutual-TLS leg to Entra.
go run ./apps/tests/devapps/imdsv2 -mode pop -trace
```

Trace mode passes a client implementing `managedidentity.MtlsHTTPClientFactory` to
`managedidentity.WithHTTPClient`. Its fresh `ClientConfigurer` keeps the tracing middleware around
the private client MSAL augments with the IMDS-issued certificate, demonstrating the same extension
point applications use for proxy, retry, logging, or policy pipelines.

`-mode pop` needs a Windows Azure VM with Credential Guard enabled — in practice a Trusted Launch
or confidential VM — whose IMDS offers the credential endpoint, and a managed identity assigned to
it. `-mode plain` works anywhere ordinary managed identity works.

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `-mode` | `pop` | `pop` for a bound `mtls_pop` token, `bearer-mtls` for a bearer token acquired over mTLS, `plain` for ordinary IMDSv1 |
| `-id-type` | `system` | `system`, or `client`, `resource`, `object` for a user-assigned identity |
| `-id` | | the identity's ID, when `-id-type` is not `system` |
| `-resource` | `https://vault.azure.net` | resource URI to request a token for |
| `-call` | | resource URL to call with the token; empty means acquire only |
| `-capabilities-only` | `false` | report what this host can do and exit |
| `-attest` | `false` | require the binding key to be attested before issuance |
| `-min-strength` | | refuse to mint below `software` or `keyguard` |
| `-force-refresh` | `false` | bypass the token cache |
| `-client-capabilities` | | comma-separated capabilities sent to Entra, e.g. `cp1` |
| `-trace` | `false` | print the mutual-TLS token request's endpoint host |

Every flag also reads an environment variable: `MI_MODE`, `MI_ID_TYPE`, `MI_ID`, `MI_RESOURCE`,
`MI_CALL`, `MI_CLIENT_CAPABILITIES`.

## Expected output

On a VM that can do it, with `-mode pop`:

```
== host capabilities ==
  GOOS:                            windows
  Source:                          DefaultToIMDS
  MaxSupportedBindingStrength:     KeyGuard
  IsMtlsPoPSupportedByHost():      true
  This host can mint a KeyGuard-bound credential, so -mode pop should succeed.

== acquiring ==
  identity:                        system-assigned
  resource:                        https://vault.azure.net
  mode:                            mtls_pop (certificate-bound token, IMDSv2)
  options:                         (none beyond the mode)

== result ==
  Metadata.TokenType:              mtls_pop
  BindingCertificate:              present (chain plus live private key)
  BindingCertificate.Leaf.Subject: <the identity's certificate subject>
  BindingCertificate.NotAfter:     <expiry, RFC3339>
  BindingCertificateThumbprint():  <base64url thumbprint>
  access token length:             1573 characters (not printed)
  expires on:                      <expiry, RFC3339>

== verification ==
  token cnf["x5t#S256"]:           <the same thumbprint>
  OK: token_type is mtls_pop and the binding thumbprint matches the token's cnf claim.
  The private key behind that certificate is held by KeyGuard and cannot be exported,
  so a stolen token cannot be replayed: the thief cannot complete the handshake.

== using the token ==
  tls.Config.GetClientCertificate: returns result.BindingCertificate
  tls.Config.Renegotiation:        RenegotiateOnceAsClient (TLS 1.2)
  Authorization header:            "mtls_pop " + result.AccessToken
  x-ms-tokenboundauth:             true
  The client above is built but not sent; pass -call <url> to send it.
```

No access token, certificate or key is ever printed. Only the `x5t#S256` thumbprint is shown, which
is public and appears in the token's own `cnf` claim.

On a host without a managed identity assigned, the same command reaches IMDS and stops there:

```
imdsv2: AcquireToken failed: managedidentity: IMDS returned 400: identity_not_found:
Managed Identity not found. To request credentials for this identity, please assign it
first. Please see aka.ms/ManagedIdentityNotFound for more details
```

## Note on the duplicated helpers

The small `section`, `kv`, `label` and `env` helpers at the bottom of `main.go` are duplicated from
the other demos in this directory rather than shared. A demo package shared across the mTLS pull
request stack would couple every pull request in it to the others and leave none of them reviewable
on its own, so roughly thirty lines of duplication is the deliberate trade-off.

## Note on error printing

The demo prints the concise error and then, when the chain carries an `errors.CallErr`, the HTTP
status and request. It does not use `errors.Verbose` for the headline: that function concatenates
every level of the error chain, and because `fmt.Errorf("...: %w")` already embeds the wrapped
message, using it would print the same sentence twice.
