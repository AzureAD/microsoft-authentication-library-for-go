# msal-go mTLS demo app

`package main` demos for the msal-go mutual-TLS (mTLS) PR stack. Each subcommand isolates one
capability and prints clearly labelled output suitable for a live presentation.

This app targets an **integration branch** that combines five as-yet-unmerged PRs. It will not compile
against `main` until that stack merges, because the samples use APIs those PRs introduce.

## Subcommands and which PR each maps to

| Subcommand         | PR                                              | Demonstrates |
|--------------------|-------------------------------------------------|--------------|
| `mtls-pop`         | **#632** mTLS PoP                               | An `mtls_pop` token: `Metadata.TokenType == "mtls_pop"`, `BindingCertificateThumbprint()`, and the token's decoded `cnf["x5t#S256"]` claim all agree — the token is bound to the certificate. |
| `bearer-over-mtls` | **#643** bearer-over-mTLS                       | The same certificate, client built with `WithSendCertificateOverMtls()`: `TokenType` is `Bearer` and `BindingCertificate` is nil — an unbound token that still travelled over the mTLS transport. |
| `cache-isolation`  | **#632 + #643**                                 | PoP and Bearer tokens for the same client/scope occupy separate cache entries and never collide (each type is re-served from cache on a second call). |
| `signer`           | **#647** `NewCredFromTLSCertificate` / **#649** signer-backed JWT assertions | A `crypto.Signer` whose private key is never exported (the exact API shape a KeyGuard/TPM/HSM key uses), driving a real client-certificate TLS handshake against a local `httptest` server. Runs fully offline. |
| `fic`              | **#633** FIC leg 2 (`NewCredFromSignedAssertionCallback`) | The developer-orchestrated two-leg federated identity credential (FIC) flow over mTLS PoP. Explains the flow always; runs live only when a second federated app is configured. Never fabricates a token. |

> KeyGuard itself is Windows/VBS-specific and is shown from a pre-existing recording. The `signer`
> subcommand here uses a **software** RSA key wrapped in a signer-only type so it demonstrates the
> identical API shape while running on any platform (CI builds this with `go build ./apps/...` on
> Linux).

## Building

```sh
go build ./apps/tests/devapps/mtls/...
# or run directly:
go run ./apps/tests/devapps/mtls <subcommand> [flags]
```

## Configuration

Defaults are the known-good lab values proven by #632's passing integration tests
(`apps/tests/integration/mtls_pop_integration_test.go`). They are public identifiers, not secrets, and
every one is overridable by flag or environment variable.

| Flag              | Env var              | Default |
|-------------------|----------------------|---------|
| `-client-id`      | `MTLS_CLIENT_ID`     | `163ffef9-a313-45b4-ab2f-c7e2f5e0e23e` |
| `-authority`      | `MTLS_AUTHORITY`     | `https://login.microsoftonline.com/bea21ebe-8b64-4d06-9f6d-6a889b120a7c` |
| `-region`         | `MTLS_REGION`        | `westus3` |
| `-cert`           | `MTLS_CERT_PATH`     | *(none — required by the network subcommands)* |
| `-scope`          | `MTLS_POP_SCOPE`     | `https://vault.azure.net/.default` |

`fic` adds `-fic-client-id` (`MTLS_FIC_CLIENT_ID`), `-fic-authority` (`MTLS_FIC_AUTHORITY`), and
`-exchange-scope` (`MTLS_EXCHANGE_SCOPE`, default `api://AzureADTokenExchange/.default`).

**The certificate is never embedded or committed.** Supply the SN/I certificate and its private key as
a single PEM file via `-cert` / `MTLS_CERT_PATH`. If it is missing, the network subcommands fail with a
clear, actionable message rather than a panic.

## Running

Offline (no certificate or network needed):

```sh
go run ./apps/tests/devapps/mtls signer
go run ./apps/tests/devapps/mtls fic          # prints the two-leg explanation, then exits
```

Network subcommands (need the SN/I certificate and the lab):

```sh
export MTLS_CERT_PATH=/path/to/sni-cert.pem
go run ./apps/tests/devapps/mtls mtls-pop
go run ./apps/tests/devapps/mtls bearer-over-mtls
go run ./apps/tests/devapps/mtls cache-isolation
```

Live two-leg FIC (needs a second federated app in addition to the certificate):

```sh
export MTLS_CERT_PATH=/path/to/sni-cert.pem
export MTLS_FIC_CLIENT_ID=<second-app-client-id>
go run ./apps/tests/devapps/mtls fic
```

Run `go run ./apps/tests/devapps/mtls <subcommand> -h` to see a subcommand's flags.
