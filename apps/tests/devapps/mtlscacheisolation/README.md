# mTLS PoP vs Bearer cache-isolation demo

A runnable demo proving that mTLS proof-of-possession tokens and Bearer tokens do **not** collide in
MSAL's token cache — even when the same client acquires both, for the same scope, with the same
certificate.

## What it demonstrates

This demo needs both features in the mTLS stack, which is why it lives with the Bearer-over-mTLS PR
rather than with the mTLS PoP one:

```go
confidential.WithMtlsProofOfPossession()    // per-request -> token_type=mtls_pop, bound to the cert
confidential.WithSendCertificateOverMtls()  // app-level   -> token_type=Bearer,   bound to nothing
```

MSAL keys an access-token cache entry on the token type together with the authentication scheme's key
ID (`AuthnSchemeKeyID` in `apps/internal/base/storage`). The `mtls_pop` scheme's key ID is the binding
certificate's `x5t#S256` thumbprint; the Bearer scheme's key ID is empty. Two keys, two entries, no
collision.

That matters because the two tokens are *not* interchangeable. An `mtls_pop` token is only accepted by
the resource over a connection presenting the same certificate; a Bearer token is accepted over any
connection. Serving one where the caller asked for the other would silently change an application's
security posture.

### Why one client, not two

The demo builds a **single** `confidential.Client`, so there is a **single** cache. That is essential:
two clients would each get their own in-memory cache, and showing that their tokens don't collide
would prove nothing at all.

One client can still produce both token types because the two options sit at different levels — the
app-level `WithSendCertificateOverMtls` makes the default acquisition a Bearer-over-mTLS one, and a
per-request `WithMtlsProofOfPossession` takes precedence over it:

```go
app, _ := confidential.New(authority, clientID, cred,
    confidential.WithSendCertificateOverMtls())

pop, _    := app.AcquireTokenByCredential(ctx, scopes,
                 confidential.WithMtlsProofOfPossession())  // -> mtls_pop, per-request option wins
bearer, _ := app.AcquireTokenByCredential(ctx, scopes)      // -> Bearer
```

### Why the calls are interleaved

The demo acquires **PoP, Bearer, PoP, Bearer**, in that order. The interleaving is what actually
proves isolation. If the two shared a cache entry, acquiring the Bearer token in between would have
overwritten the PoP entry, and the second PoP call would have gone back to Entra ID — or, worse,
returned the Bearer token. Both second calls being served from cache, each returning its own earlier
token with its own token type, is a result that can only happen if the entries are distinct.

The demo asserts, and prints:

1. The same client produced both an `mtls_pop` and a `Bearer` token.
2. The two access tokens are different values — no entry was shared.
3. Each repeat call returned its **own** earlier token, with its own token type, despite the other
   type having been acquired in between.
4. Both repeat calls were served from cache.
5. Only the `mtls_pop` result is certificate-bound (`BindingCertificate` non-nil); the Bearer result
   is not.

## Running it

```sh
go run ./apps/tests/devapps/mtlscacheisolation -cert /path/to/sni-cert.pem
```

`-cert` points at a PEM file containing the SN/I certificate **and** its private key. Nothing about
the certificate is embedded in this program or written to its output, and no certificate is committed
to this repository. Access tokens are never printed in full — only a short, non-reversible
head/tail fingerprint, so two tokens can be told apart on screen.

If your certificate is a PFX/PKCS#12 file (the usual case on Windows), convert it once:

```sh
openssl pkcs12 -in cert.pfx -nodes -out cert.pem
```

`-nodes` (`-noenc` in OpenSSL 3.x) is required — it leaves the private key unencrypted.
`CertFromPEM` ignores its password parameter and skips encrypted key blocks, so a key left
encrypted fails with the unhelpful `no private key found`. Protect the file with filesystem
permissions instead. Block order does not matter; the leaf is found by matching the private key.

Unlike the sibling [`bearerovermtls`](../bearerovermtls) demo, this one has no offline path: it needs
the certificate, network access, and an mTLS-enabled app registration, because the whole point is what
the cache does with two real tokens.

### Flags

Every flag falls back to an environment variable, then to a known-good lab default. The defaults match
the constants used by the passing integration tests in
`apps/tests/integration/mtls_pop_integration_test.go`; they are public identifiers, not secrets.

| Flag | Env var | Default |
|---|---|---|
| `-client-id` | `MTLS_CLIENT_ID` | `163ffef9-a313-45b4-ab2f-c7e2f5e0e23e` |
| `-authority` | `MTLS_AUTHORITY` | `https://login.microsoftonline.com/bea21ebe-8b64-4d06-9f6d-6a889b120a7c` |
| `-region` | `MTLS_REGION` | `westus3` (empty uses the global `mtlsauth` endpoint) |
| `-cert` | `MTLS_CERT_PATH` | *(none — required)* |
| `-scope` | `MTLS_SCOPE` | `https://vault.azure.net/.default` |

mTLS PoP requires a **tenanted** authority on a `login.*` host; `/common`, `/organizations` and
`/consumers` are rejected.

## Expected output

Token fingerprints and thumbprints will differ from run to run:

```
== configuration ==
  authority:                       https://login.microsoftonline.com/bea21ebe-...
  client id:                       163ffef9-a313-45b4-ab2f-c7e2f5e0e23e
  region:                          westus3
  scope:                           https://vault.azure.net/.default
  certificate x5t#S256:            <base64url SHA-256 of the leaf>

== interleaved acquisitions (same client, same scope, same certificate) ==
  PoP #1 token_type:               mtls_pop
  PoP #1 source:                   identity-provider
  PoP #1 BindingCertificate:       bound to <same x5t#S256 as above>
  PoP #1 token fingerprint:        eyJ0eXAi...bGciOiJS
  Bearer #1 token_type:            Bearer
  Bearer #1 source:                identity-provider
  Bearer #1 BindingCertificate:    <nil>
  Bearer #1 token fingerprint:     eyJ0eXAi...VCJ9.eyJ
  PoP #2 token_type:               mtls_pop
  PoP #2 source:                   cache
  PoP #2 BindingCertificate:       bound to <same x5t#S256 as above>
  PoP #2 token fingerprint:        eyJ0eXAi...bGciOiJS
  Bearer #2 token_type:            Bearer
  Bearer #2 source:                cache
  Bearer #2 BindingCertificate:    <nil>
  Bearer #2 token fingerprint:     eyJ0eXAi...VCJ9.eyJ

== verification ==
  PASS  the same client produced both an "mtls_pop" and a "Bearer" token.
  PASS  the two access tokens are different values - no entry was shared.
  PASS  each repeat call returned its OWN earlier token, with its own token type,
        even though the other type was acquired in between.
  PASS  PoP #2 was served from cache.
  PASS  Bearer #2 was served from cache.
  PASS  only the mtls_pop result is certificate-bound (BindingCertificate non-nil);
        the Bearer result is not. Serving one for the other would silently change
        an application's security posture, which is why the entries are separate.
```

The key lines are `PoP #2 token fingerprint` matching `PoP #1`, and `Bearer #2` matching `Bearer #1`,
with both sourced from `cache`. The demo exits non-zero if any of those cross-checks fails.

A repeat call that is *not* served from cache is reported as a `NOTE` rather than a failure: MSAL
legitimately refreshes a token that is close to expiry, and failing on that would report a cache miss
as a correctness bug. The token-value and token-type cross-checks stay hard either way.

## Note on duplicated helpers

The certificate-loading, flag and printing helpers in `main.go` are duplicated in each demo under
`apps/tests/devapps` instead of being shared. That is deliberate. Each PR in the mTLS stack must be
reviewable and runnable on its own branch, and a shared demo package would couple this demo to demos
for features that only exist on sibling branches. Copying a few dozen lines is the cheaper trade.
