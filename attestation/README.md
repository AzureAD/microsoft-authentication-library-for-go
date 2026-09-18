# Optional KeyGuard attestation for MSAL Go

This module adds KeyGuard attestation to managed identity acquisition without
making the native attestation library part of ordinary MSAL Go applications.

```sh
go get github.com/AzureAD/microsoft-authentication-library-for-go/attestation
```

```go
import (
    "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
    "github.com/AzureAD/microsoft-authentication-library-for-go/attestation"
)

result, err := client.AcquireToken(ctx, "https://vault.azure.net",
    managedidentity.WithMtlsProofOfPossession(),
    attestation.WithSupport(),
)
```

`WithSupport` is per acquisition and lazy. A Windows amd64 application that
imports this module embeds the authentic `AttestationClientLib.dll` from
`Microsoft.Azure.Security.KeyGuardAttestation` 1.1.5 in its executable. An
application that does not import this module does not link or embed the DLL.

On first use, the module:

1. Verifies the embedded bytes against the pinned SHA-256.
2. Uses a cross-process file lock, a same-directory temporary file, and atomic
   replacement to materialize the DLL at
   `%LOCALAPPDATA%\Microsoft\MSAL\attestation\1.1.5\win-x64\AttestationClientLib.dll`.
   Lock contention is retried for up to five seconds and then fails closed.
3. Rejects reparse-point ancestry, derives the canonical absolute path from the
   verified file handle, and re-verifies the on-disk hash and Authenticode
   signature while holding the file and ancestor handles open without write or
   delete sharing.
4. Loads that exact absolute path with dependencies restricted to `System32`.

It never searches the working directory or `%PATH%` and never falls back to a
different DLL. Any extraction, integrity, signature, loading, initialization,
or attestation failure wraps `managedidentity.ErrAttestationUnavailable` (or a
more specific managed identity attestation error) and fails the acquisition;
there is no downgrade to an unattested credential.

The latest supported [Microsoft Visual C++ v14 Redistributable (x64)][vc-redist]
is a Windows runtime prerequisite. Its runtime DLLs, including
`VCRUNTIME140_1.dll`, must be installed in `System32`; the module intentionally
does not load application-local or `%PATH%` copies of those dependencies.

[vc-redist]: https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist

The packaged DLL supports Windows amd64. The module compiles on other platforms,
but an acquisition fails explicitly with
`managedidentity.ErrMtlsNotSupportedForPlatform` rather than downgrading; the
unsupported-platform provider stub also reports
`managedidentity.ErrAttestationUnavailable` if invoked.
