# Bearer-over-mTLS demo

A runnable demo of `confidential.WithSendCertificateOverMtls()`.

## What it demonstrates

The option makes a confidential client present its certificate credential as the client certificate
on the mutual-TLS handshake to the token endpoint, and routes the request to the mTLS endpoint
(`mtlsauth.*`) — but the token that comes back is an ordinary, **unbound Bearer token**.

That contrast with mTLS proof-of-possession is the entire point:

| | `WithMtlsProofOfPossession()` | `WithSendCertificateOverMtls()` |
|---|---|---|
| Where it goes | per **request** | per **app** (`confidential.New`) |
| `Metadata.TokenType` | `mtls_pop` | `Bearer` |
| `AuthResult.BindingCertificate` | the binding certificate | `nil` |
| Token's `cnf["x5t#S256"]` claim | the certificate thumbprint | absent |
| Presenting the token to the resource | requires the same certificate on the connection | no certificate needed |
| Cache key | fenced by the certificate thumbprint | the ordinary Bearer key |

In both cases the token request itself travels over mutual TLS to `mtlsauth.*`. The difference is
what the certificate *buys*: with `WithSendCertificateOverMtls` it authenticates the **transport**
to Entra ID only, and the resulting token is bound to nothing.

The demo prints three independent pieces of evidence that the token is unbound — `TokenType` is
`Bearer`, `BindingCertificate` is `nil`, and the decoded access token carries no `cnf["x5t#S256"]`
claim — then acquires a second time to show the token was cached under the ordinary Bearer key.

### API shape

```go
certs, key, _ := confidential.CertFromPEM(pem, "")
cred, _ := confidential.NewCredFromCert(certs, key)   // a certificate credential is REQUIRED

app, _ := confidential.New(authority, clientID, cred,
    confidential.WithSendCertificateOverMtls())        // APP-level option, not per-call

res, _ := app.AcquireTokenByCredential(ctx, scopes)    // no per-request option
// res.Metadata.TokenType     == "Bearer"   <- NOT bound to the certificate
// res.BindingCertificate     == nil
```

### Scope of the option

`WithSendCertificateOverMtls` is honored by the flows that send a client credential: **client
credentials**, **on-behalf-of**, **authorization code**, and **silent refresh**. It is *not* applied
to `AcquireTokenByUsernamePassword` (which sends no client credential at all) or to
`AcquireTokenByUserFederatedIdentityCredential`; those two keep using the regular token endpoint.
This matches MSAL .NET's `SendCertificateOverMtls`.

A per-request `WithMtlsProofOfPossession()` **always takes precedence** over the app-level flag, so
the same client can still mint a bound `mtls_pop` token on demand. See the sibling
[`mtlscacheisolation`](../mtlscacheisolation) demo, which relies on exactly that.

`confidential.New` returns an error for any non-certificate credential:

```
WithSendCertificateOverMtls requires a certificate credential, such as one from NewCredFromCert
```

## Running it

```sh
go run ./apps/tests/devapps/bearerovermtls -cert /path/to/sni-cert.pem
```

`-cert` points at a PEM file containing the SN/I certificate **and** its private key. Nothing about
the certificate is embedded in this program or written to its output, and no certificate is committed
to this repository.

The first section (the credential guardrail) runs entirely offline, so `go run
./apps/tests/devapps/bearerovermtls` with no arguments still prints something useful before it stops
with an actionable "no certificate supplied" message. Everything after it needs the certificate,
network access, and an mTLS-enabled app registration.
### Flags

Every flag falls back to an environment variable, then to a known-good lab default. The defaults
match the constants used by the passing integration tests in
`apps/tests/integration/mtls_pop_integration_test.go`; they are public identifiers, not secrets.

| Flag | Env var | Default |
|---|---|---|
| `-client-id` | `MTLS_CLIENT_ID` | `163ffef9-a313-45b4-ab2f-c7e2f5e0e23e` |
| `-authority` | `MTLS_AUTHORITY` | `https://login.microsoftonline.com/bea21ebe-8b64-4d06-9f6d-6a889b120a7c` |
| `-region` | `MTLS_REGION` | `westus3` (empty uses the global `mtlsauth` endpoint) |
| `-cert` | `MTLS_CERT_PATH` | *(none — required for everything past the guardrail)* |
| `-scope` | `MTLS_SCOPE` | `https://vault.azure.net/.default` |

## Expected output

The first two sections are verbatim from a real run; they need no certificate and no network:

```
== configuration ==
  authority:                       https://login.microsoftonline.com/bea21ebe-8b64-4d06-9f6d-6a889b120a7c
  client id:                       163ffef9-a313-45b4-ab2f-c7e2f5e0e23e
  region:                          westus3
  scope:                           https://vault.azure.net/.default

== guardrail: the option requires a certificate credential (offline) ==
  New(secret credential):          rejected
  error:                           WithSendCertificateOverMtls requires a certificate credential, such as one from NewCredFromCert
  PASS  only a certificate credential can be sent over mTLS.
```

With a certificate and network access, the run continues in this shape (token values and thumbprints
will differ):

```
== certificate ==
  x5t#S256:                        <base64url SHA-256 of the leaf>

== acquire ==
  Metadata.TokenType:              Bearer
  Metadata.TokenSource:            identity-provider
  AuthResult.BindingCertificate:   <nil>
  token cnf["x5t#S256"]:           <absent - the token is unbound>

== acquire again (same client, same scope) ==
  Metadata.TokenType:              Bearer
  Metadata.TokenSource:            cache
  same access token as #1:         true

== verification ==
  PASS  Metadata.TokenType == "Bearer" (not mtls_pop).
  PASS  AuthResult.BindingCertificate is nil - MSAL bound the token to nothing.
  PASS  the token carries no cnf["x5t#S256"] confirmation claim.
  PASS  the second call was served from the ordinary Bearer cache entry.

  The certificate authenticated the TLS connection to the mtlsauth.* endpoint,
  but the token it returned is an ordinary Bearer token: it can be presented to
  the resource over a plain connection, with no certificate involved.
```

The demo exits non-zero if any of the first three checks fails. A second call that is *not* served
from cache is reported as a `NOTE` rather than a failure: MSAL legitimately refreshes a token that is
close to expiry, and failing on that would report a cache miss as a correctness bug.

## Note on duplicated helpers

The certificate-loading, flag and printing helpers in `main.go` are duplicated in each demo under
`apps/tests/devapps` instead of being shared. That is deliberate. Each PR in the mTLS stack must be
reviewable and runnable on its own branch, and a shared demo package would couple this demo to demos
for features that only exist on sibling branches. Copying a few dozen lines is the cheaper trade.
