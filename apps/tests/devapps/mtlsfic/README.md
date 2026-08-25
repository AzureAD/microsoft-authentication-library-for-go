# Two-leg FIC over mTLS proof-of-possession — demo

A standalone, runnable demo of the feature this PR adds: `confidential.NewCredFromSignedAssertionCallback`,
the credential for the second leg of a developer-orchestrated two-leg federated identity credential
(FIC) flow over mTLS proof-of-possession.

## What it demonstrates

The application orchestrates two mTLS PoP calls and carries the result of the first into the second:

| | Call | Result |
|---|---|---|
| **Leg 1** | An ordinary `WithMtlsProofOfPossession()` acquisition (the mTLS PoP capability this branch builds on) for scope `api://AzureADTokenExchange/.default` | A certificate-bound **federated assertion**, plus the `*tls.Certificate` it is bound to. `AccessToken` here is an assertion for leg 2, **not** a usable resource token. |
| **Leg 2** | `NewCredFromSignedAssertionCallback`, whose callback *runs leg 1* and returns one `SignedAssertion{Assertion, BindingCertificate}` | The final `mtls_pop` resource token, bound to leg 1's certificate. |

The points the demo exists to make, each verifiable in this branch's source:

- **The assertion and its binding certificate are returned together, by design.** There is no
  `WithBindingCertificate()` call-site option, and that absence *is* the enforcement — values you
  cannot supply separately are values you cannot mismatch. `Client.resolveMtlsBindingCert` in
  `apps/confidential/confidential.go` takes a callback certificate from nowhere else. This mirrors
  MSAL .NET's `ClientSignedAssertion.TokenBindingCertificate`.
- **`BindingCertificate` may be nil**, in which case MSAL falls back to the client's own certificate
  credential, and fails with guidance if it has none.
- **Leg 1 belongs *inside* the callback, not captured before it.** Under mTLS PoP the binding
  certificate partitions the token cache and selects the TLS connection, so MSAL resolves the
  callback *before* consulting the cache — meaning it is re-invoked on later acquisitions. A callback
  that closed over one pre-computed leg-1 result would keep replaying an assertion that eventually
  expires, bound to a certificate that may since have rotated. That bug is invisible in a one-shot
  demo and bites a long-running service, so this demo calls leg 1 inside the callback and reports
  whether the repeat call was absorbed by `leg1App`'s cache.
- **Leg 2's wire format:** `client_assertion` *returns*, carried with
  `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-pop`
  (`grant.ClientAssertionPoP` in `apps/internal/oauth/ops/internal/grant/grant.go`).
- **The assertion story inverts across the stack:** vanilla certificate auth sends `jwt-bearer`;
  plain mTLS PoP sends *no client assertion at all* (`FromClientCertificate` — the TLS handshake
  authenticates the client); FIC leg 2 sends the assertion again, as `jwt-pop`.

## Running it

Explain the flow, no certificate or network needed:

```sh
go run ./apps/tests/devapps/mtlsfic
```

Run both legs live against the lab (needs the SN/I certificate and network access):

```sh
export MTLS_CERT_PATH=/path/to/sni-cert.pem
go run ./apps/tests/devapps/mtlsfic
```

Point leg 2 at a genuinely separate federated app:

```sh
go run ./apps/tests/devapps/mtlsfic -cert /path/to/sni-cert.pem -fic-client-id <second-app-client-id>
```

### Configuration

Defaults are the public lab identifiers used by `TestTwoLegFICMtlsPoP_SNI` in
`apps/tests/integration/mtls_pop_integration_test.go`. They are identifiers, not secrets, and every
one is overridable.

| Flag | Env var | Default |
|---|---|---|
| `-cert` | `MTLS_CERT_PATH` | *(none — required for a live run)* |
| `-client-id` | `MTLS_CLIENT_ID` | `163ffef9-a313-45b4-ab2f-c7e2f5e0e23e` |
| `-authority` | `MTLS_AUTHORITY` | `https://login.microsoftonline.com/bea21ebe-8b64-4d06-9f6d-6a889b120a7c` |
| `-fic-client-id` | `MTLS_FIC_CLIENT_ID` | *(falls back to `-client-id`)* |
| `-fic-authority` | `MTLS_FIC_AUTHORITY` | *(falls back to `-authority`)* |
| `-exchange-scope` | `MTLS_EXCHANGE_SCOPE` | `api://AzureADTokenExchange/.default` |
| `-scope` | `MTLS_POP_SCOPE` | `https://vault.azure.net/.default` |
| `-region` | `MTLS_REGION` | *(empty — global endpoint)* |

`-region` defaults to empty because the global endpoint is what `TestTwoLegFICMtlsPoP_SNI` actually
exercises for this flow. Set it to opt into the regional token endpoint.

**No certificate, key or secret is committed here.** Supply the SN/I certificate and its private key
as a single PEM file. Without `-cert` the demo prints the explanation and exits 0; it never
fabricates a token.

## Expected output

Without a certificate it prints the `Two-leg FIC over mTLS proof-of-possession` section explaining
the flow, then `live run skipped`.

With a certificate it additionally prints `live run`, `leg 1`, `leg 2` and `result` sections. The
`result` section reports the final `token_type`, the thumbprints, and what the callback itself did —
in this shape (illustrative, since running it needs a lab certificate and network):

```
  final token_type:                mtls_pop
  final binding cert x5t#S256:     <thumbprint>
  final token cnf[x5t#S256]:       <the same thumbprint>
  leg 1 inside callback:           served from cache (callback fired 1x)
```

It ends with a line confirming that four thumbprints agree: the certificate on disk, leg 1's binding
certificate, leg 2's, and the `cnf["x5t#S256"]` claim the issuer put in the final token. That last
one is the meaningful proof — it is the issuer's own statement of what the token is bound to, not
MSAL echoing a certificate back at us. Any mismatch, or a `token_type` that is not `mtls_pop` on
either leg, exits non-zero rather than reporting success.

The `leg 1 inside callback` line is how the demo backs up its own claim that re-running leg 1 in the
callback is cheap. If that repeat acquisition goes to the network instead of the cache — legitimate
when the first assertion was already near expiry — it is reported as a `NOTE` rather than treated as
a failure.

## Caveat: same-app by default

By default both legs use the same app and tenant, because that is the only configuration proven to
work in our lab — the existing integration test `TestTwoLegFICMtlsPoP_SNI` has exactly this shape.
That proves the mechanics and the wire format, **but it is not a genuine cross-identity hop.** The
demo says so on stdout when it detects that shape. Pass `-fic-client-id` (and `-fic-authority` if the
second app lives in another tenant) to exercise a real second federated app that trusts leg 1's
assertion.

## Note for reviewers

A handful of small helpers (`loadCertificate`, `cnfThumbprintFromToken`, `thumbprintOfCert`,
`section`, `kv`, `env`) are duplicated in `main.go` rather than shared with the sibling demos in the
other PRs of this mTLS stack. That is deliberate: a shared demo package would make this demo depend
on code that lands in a different pull request, reintroducing the cross-PR coupling that makes a
stack-wide demo impossible to review on its own. About thirty self-contained lines is the intended
price of keeping this PR reviewable by itself.
