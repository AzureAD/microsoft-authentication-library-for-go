# mTLS proof-of-possession demo

A runnable `package main` demo of **mTLS proof-of-possession (PoP)**: an access token that is
cryptographically bound to the certificate presented on the mutual-TLS handshake to the token
endpoint, instead of a plain bearer token that anyone who obtains it can replay.

## What it demonstrates

The entire opt-in is one per-call option:

```go
cred, _ := confidential.NewCredFromCert(certs, key)
app, _ := confidential.New(authority, clientID, cred) // authority must be tenanted
res, _ := app.AcquireTokenByCredential(ctx, scopes,
    confidential.WithMtlsProofOfPossession())
```

and the result carries everything needed to use the token:

| Field | Value |
|---|---|
| `res.Metadata.TokenType` | `"mtls_pop"`, not `"Bearer"` |
| `res.BindingCertificate` | `*tls.Certificate` — the chain plus the live private key |
| `res.BindingCertificateThumbprint()` | equals the token's `cnf["x5t#S256"]` claim |

The demo acquires a token, decodes the token's `cnf` claim itself, and asserts that the thumbprint
MSAL reported and the thumbprint inside the token agree. That is the proof the token is bound.

Redeeming the token then takes **both halves**, and neither works alone:

```go
tls.Config{Certificates: []tls.Certificate{*res.BindingCertificate}}
req.Header.Set("Authorization", "mtls_pop "+res.AccessToken)
```

The `using the token` section builds exactly that client and request. It only sends it when
`-resource` is supplied.

### Three things that are easy to get wrong

- **`WithX5C()` is inert in this flow.** mTLS PoP mints no client assertion at all, so there is no
  JWT header for an `x5c` array to ride in. The chain is presented on the TLS handshake instead.
  Passing `WithX5C()` is harmless but changes nothing about an mTLS PoP call.
- **The token endpoint is rewritten from `login.*` to `mtlsauth.*`** (regionalized to
  `{region}.mtlsauth.*` when a region is configured). Public-cloud login hosts collapse onto the
  shared `mtlsauth.microsoft.com` family.
- **The wire delta versus plain certificate authentication is a subtraction.** `client_assertion`,
  `client_assertion_type` and `req_cnf` are all *absent*. The mutual-TLS handshake both
  authenticates the client and binds the token.

Run with `-trace` to see the last two on the actual request rather than taking them on faith.

Two more constraints worth knowing: the authority must be **tenanted** (`/common`,
`/organizations` and `/consumers` are rejected before any network call), and mTLS PoP is
**app-only** — it exists on `AcquireTokenByCredential` and nowhere else, because the binding
certificate authenticates the application rather than a user.

## Building and running

```sh
go build ./apps/tests/devapps/mtlspop
go run ./apps/tests/devapps/mtlspop -h
```

A certificate is required. **Nothing is embedded or committed** — supply the certificate and its
private key as a single PEM file at runtime:

```sh
export MTLS_CERT_PATH=/path/to/cert.pem
go run ./apps/tests/devapps/mtlspop
```

If your certificate is a PFX/PKCS#12 file (the usual case on Windows), convert it once:

```sh
openssl pkcs12 -in cert.pfx -nodes -out cert.pem
```

`-nodes` (`-noenc` in OpenSSL 3.x) is required — it leaves the private key unencrypted.
`CertFromPEM` ignores its password parameter and skips encrypted key blocks, so a key left
encrypted fails with the unhelpful `no private key found`. Protect the file with filesystem
permissions instead. Block order does not matter; the leaf is found by matching the private key.

Show the wire format, and call a resource end to end:

```sh
go run ./apps/tests/devapps/mtlspop -trace
go run ./apps/tests/devapps/mtlspop -resource "https://mtlstb.graph.microsoft.com/v1.0/applications?\$top=1"
```

## Configuration

Defaults are the known-good lab values used by
`apps/tests/integration/mtls_pop_integration_test.go`. They are public identifiers, not secrets.

| Flag | Env var | Default |
|---|---|---|
| `-client-id` | `MTLS_CLIENT_ID` | `163ffef9-a313-45b4-ab2f-c7e2f5e0e23e` |
| `-authority` | `MTLS_AUTHORITY` | `https://login.microsoftonline.com/bea21ebe-8b64-4d06-9f6d-6a889b120a7c` |
| `-region` | `MTLS_REGION` | `westus3` (pass `-region ""` for the global endpoint) |
| `-cert` | `MTLS_CERT_PATH` | *(none — required)* |
| `-scope` | `MTLS_POP_SCOPE` | `https://vault.azure.net/.default` |
| `-resource` | `MTLS_POP_RESOURCE` | *(none — acquire only)* |
| `-trace` | — | `false` |

Both the resource scope and the app must be allow-listed for mTLS PoP by the identity provider, so
this runs against the lab app and tenant above unless you have your own.

## Expected output

With a valid certificate against the lab, with `-trace` on. Thumbprints and the token endpoint
depend on your certificate and region.

```
== mTLS proof-of-possession ==
  authority:                       https://login.microsoftonline.com/bea21ebe-8b64-4d06-9f6d-6a889b120a7c
  client id:                       163ffef9-a313-45b4-ab2f-c7e2f5e0e23e
  scope:                           https://vault.azure.net/.default
  region:                          westus3
  certificate subject:             <your cert CN>
  certificate x5t#S256:            <base64url SHA-256 of the leaf>

== token request (mutual-TLS leg) ==
  method:                          POST
  endpoint host:                   westus3.mtlsauth.microsoft.com
  URL:                             https://westus3.mtlsauth.microsoft.com/<tenant>/oauth2/v2.0/token
  body parameters:                 client_id, grant_type, scope, token_type
  token_type requested:            mtls_pop
  client_assertion:                absent
  client_assertion_type:           absent
  req_cnf:                         absent
  The client certificate is presented on this handshake; that is what authenticates the
  client and binds the token, which is why no client_assertion is needed.

== result ==
  Metadata.TokenType:              mtls_pop
  Metadata.TokenSource:            identity provider (network)
  BindingCertificateThumbprint():  <same value as certificate x5t#S256 above>
  BindingCertificate.Leaf:         present (parsed public leaf)
  BindingCertificate.PrivateKey:   present (live signer, for tls.Config)
  access token length:             2437 characters (not printed)
  token cnf["x5t#S256"]:           <same value again>

== verification ==
  OK: token_type is mtls_pop and the binding thumbprint matches the token's cnf claim.
  The token is cryptographically bound to the certificate presented on the TLS handshake.

== using the token ==
  tls.Config.Certificates:         []tls.Certificate{*result.BindingCertificate}
  Authorization header:            "mtls_pop " + result.AccessToken
  resource:                        https://mtlstb.graph.microsoft.com/v1.0/applications?$top=1
  The client and request above are built but not sent; pass -resource <url> to send it.
```

The access token is never printed; only its length and its public `cnf` claim are shown.

Without a certificate the demo exits non-zero with an actionable message rather than panicking:

```
mtlspop: no certificate supplied: pass -cert <path-to-pem> or set MTLS_CERT_PATH to a PEM file containing the certificate and its private key
```

## A note on the duplicated helpers

`loadCertificate`, `cnfThumbprintFromToken`, `thumbprintOfCert`, `section`, `kv`, `label` and `env`
are copied into `main.go` rather than shared with the sibling mTLS demos. That is deliberate: a
shared demo package would couple every pull request in the mTLS stack to the others and leave none
of them reviewable on its own. Roughly thirty lines of duplication is the price of each demo
standing alone with the change it demonstrates.
