# AttestationClientLib.dll

`AttestationClientLib.dll` is the unmodified Windows x64 native asset from:

- Package: `Microsoft.Azure.Security.KeyGuardAttestation`
- Version: `1.1.5`
- Package path: `runtimes/win-x64/native/AttestationClientLib.dll`
- Source: <https://www.nuget.org/packages/Microsoft.Azure.Security.KeyGuardAttestation/1.1.5>
- SHA-256: `90dfcce20e1a74519b49796eeee17e6e59a257c3acf754f454a49380d28a568b`
- Authenticode signer: `Microsoft Corporation`
- Signer certificate thumbprint: `3F56A45111684D454E231CFDC4DA5C8D370F9816`

The package declares the MIT license. The expected SHA-256 is also pinned in
`provider_windows_amd64.go`; runtime loading requires both that exact hash and a
valid Windows Authenticode verification result.
