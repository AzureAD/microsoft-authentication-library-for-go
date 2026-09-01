# Microsoft Authentication Library (MSAL) for Go

The Microsoft Authentication Library (MSAL) for Go is part of the [Microsoft identity platform for developers](https://aka.ms/aaddevv2) (formerly named Azure AD) v2.0. It allows you to sign in users or apps with Microsoft identities ([Azure AD](https://azure.microsoft.com/services/active-directory/) and [Microsoft Accounts](https://account.microsoft.com)) and obtain tokens to call Microsoft APIs such as [Microsoft Graph](https://graph.microsoft.io/) or your own APIs registered with the Microsoft identity platform. It is built using industry standard OAuth2 and OpenID Connect protocols.

The latest code resides in the `dev` branch.

Quick links:

| [Getting Started](https://docs.microsoft.com/azure/active-directory/develop/#quickstarts) | [GoDoc](https://pkg.go.dev/github.com/AzureAD/microsoft-authentication-library-for-go/apps) | [Wiki](https://github.com/AzureAD/microsoft-authentication-library-for-go/wiki) | [Samples](https://github.com/AzureAD/microsoft-authentication-library-for-go/tree/main/apps/tests/devapps) | [Support](README.md#community-help-and-support) | [Feedback](https://forms.office.com/r/s4waBAytFJ) |
| ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |

## Build Status

![Go](https://github.com/AzureAD/microsoft-authentication-library-for-go/workflows/Go/badge.svg?branch=dev)

## Installation

### Setting up Go
To install Go, visit [this link](https://golang.org/dl/).

### Installing MSAL Go
`go get -u github.com/AzureAD/microsoft-authentication-library-for-go/`

## Usage
Before using MSAL Go, you will need to [register your application with the Microsoft identity platform](https://docs.microsoft.com/azure/active-directory/develop/quickstart-v2-register-an-app).

### Acquiring Tokens

Acquiring tokens with MSAL Go follows this general pattern. There might be some slight differences for other token acquisition flows. Here is a basic example:

1. Create a client. MSAL separates [public and confidential client applications](https://tools.ietf.org/html/rfc6749#section-2.1), so call `public.New()` or `confidential.New()` to create the appropriate client for your application.

   * Initializing a public client:

    ```go
    import "github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"

    publicClient, err := public.New("client_id", public.WithAuthority("https://login.microsoftonline.com/your_tenant"))
    ```

   * Initializing a confidential client:

    ```go
    import "github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"

    // confidential clients have a credential, such as a secret or a certificate
    cred, err := confidential.NewCredFromSecret("client_secret")
    if err != nil {
        // TODO: handle error
    }
    confidentialClient, err := confidential.New("https://login.microsoftonline.com/your_tenant", "client_id", cred)
    ```
    * Initializing a Managed Identity client for SystemAssigned:

    ```go
    import mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"

    // Managed identity client have a type of ID required, SystemAssigned or UserAssigned
	miSystemAssigned, err := mi.New(mi.SystemAssigned())
    if err != nil {
        // TODO: handle error
    }
    ```
    * Initializing a Managed Identity client for UserAssigned:

    ```go
    import mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"

    // Managed identity client have a type of ID required, SystemAssigned or UserAssigned
	miSystemAssigned, err := mi.New(mi.UserAssignedClientID("YOUR_CLIENT_ID"))
    if err != nil {
        // TODO: handle error
    }
    ```

1. Call `AcquireTokenSilent()` to look for a cached token. If `AcquireTokenSilent()` returns an error, call another `AcquireToken...` method to authenticate.

    * Public clients should specify a user account, if one is available:

    ```go
    // If your application previously authenticated a user, call AcquireTokenSilent with that user's account
    // to use cached authentication data. This example shows choosing an account from the cache, however this
    // isn't always necessary because the AuthResult returned by authentication methods includes user account
    // information.
    accounts, err := client.Accounts(context.TODO())
    if err != nil {
        // TODO: handle error
    }
    if len(accounts) > 0 {
        // There may be more accounts; here we assume the first one is wanted.
        // AcquireTokenSilent returns a non-nil error when it can't provide a token.
        result, err = client.AcquireTokenSilent(context.TODO(), scopes, public.WithSilentAccount(accounts[0]))
    }
    if err != nil || len(accounts) == 0 {
        // cache miss, authenticate a user with another AcquireToken* method
        result, err = client.AcquireTokenInteractive(context.TODO(), scopes)
        if err != nil {
            // TODO: handle error
        }
    }
    // TODO: save the authenticated user's account, use the access token
    userAccount := result.Account
    accessToken := result.AccessToken
    ```

    * Confidential clients can simply call `AcquireTokenSilent()`:

    ```go
    scopes := []string{"scope"}
    result, err := confidentialClient.AcquireTokenSilent(context.TODO(), scopes)
    if err != nil {
        // cache miss, authenticate with another AcquireToken... method
        result, err = confidentialClient.AcquireTokenByCredential(context.TODO(), scopes)
        if err != nil {
            // TODO: handle error
        }
    }
    accessToken := result.AccessToken
    ```

    * ManagedIdentity client can simply call `AcquireToken()`:
    ```go
    resource := "<Your resource>"
	result, err := miSystemAssigned.AcquireToken(context.TODO(), resource)
	if err != nil {
        // TODO: handle error
	}
    accessToken := result.AccessToken
    ```

## Loading Certificates from PEM

`confidential.CertFromPEM` loads a certificate and an **unencrypted** private key from PEM data for
use with `NewCredFromCert`.

> **Security note — encrypted PEM is not supported:** `CertFromPEM` rejects legacy RFC 1423
> encrypted PEM blocks (those with a `DEK-Info` header, e.g. `DEK-Info: DES-EDE3-CBC,...`) with an
> error. That format relies on a weak key derivation function (a single MD5 iteration) and obsolete
> DES/3DES ciphers, which provide little protection against offline password-guessing attacks.
>
> Provide the private key **unencrypted** and protect it with filesystem permissions. You can strip
> legacy encryption with OpenSSL:
>
> ```sh
> openssl pkcs8 -topk8 -nocrypt -in legacy.key -out key.pem
> ```

## mTLS Proof-of-Possession (SNI)

A confidential client configured with a Subject Name + Issuer (SN/I) certificate can request an
**mTLS-bound proof-of-possession** token (`token_type=mtls_pop`) instead of a Bearer token. The same
certificate used for the credential is presented as the **client TLS certificate** in the mutual-TLS
handshake to Entra ID, and the returned token is cryptographically bound to that certificate
(`cnf/x5t#S256`). Opt in per call with `WithMtlsProofOfPossession()`:

```go
certs, key, _ := confidential.CertFromPEM(pem, "")
cred, _ := confidential.NewCredFromCert(certs, key)

// The authority must be tenanted (not /common, /organizations, or /consumers).
app, _ := confidential.New("https://login.microsoftonline.com/your_tenant", "client_id", cred)

result, err := app.AcquireTokenByCredential(context.TODO(),
    []string{"https://vault.azure.net/.default"},
    confidential.WithMtlsProofOfPossession())
if err != nil {
    // TODO: handle error
}
_ = result.Metadata.TokenType                  // "mtls_pop"
_ = result.BindingCertificate                  // *tls.Certificate bound to the token (leaf + private key)
_ = result.BindingCertificateThumbprint()      // base64url SHA-256 (x5t#S256)
```

Notes:

- **Binding is via the TLS certificate**: on the mTLS PoP path no `client_assertion` and no `req_cnf`
  are sent — the certificate presented on the TLS handshake is the proof. This omission is specific to
  mTLS PoP: a normal Bearer acquisition with the same SN/I certificate (i.e. without
  `WithMtlsProofOfPossession()`) still signs and sends a `client_assertion`. The endpoint is rewritten
  from `login.*` to `mtlsauth.*`.
- **Using the token**: present it to the resource with the `mtls_pop` authorization scheme (not
  `Bearer`) and `result.BindingCertificate` as the client certificate on the TLS handshake, so the
  connection matches the token binding. `BindingCertificate` is a `*tls.Certificate` that carries both
  the parsed leaf (`.Leaf`) and the private key MSAL used, so it goes straight into
  `tls.Config.Certificates` — including when the key is non-exportable (KeyGuard/CNG/HSM) and the
  credential came from [`NewCredFromTLSCertificate`](#non-exportable-keys-keyguard-cng-hsm), because
  `crypto/tls` only needs a `crypto.Signer`:

  ```go
  transport := http.DefaultTransport.(*http.Transport).Clone()
  transport.TLSClientConfig = &tls.Config{
      Certificates: []tls.Certificate{*result.BindingCertificate},
      MinVersion:   tls.VersionTLS12,
  }
  req, _ := http.NewRequest(http.MethodGet, resourceURL, nil)
  req.Header.Set("Authorization", "mtls_pop "+result.AccessToken)
  resp, err := (&http.Client{Transport: transport}).Do(req)
  ```
- **App-only**: mTLS PoP is a client-credentials-only mechanism — the binding certificate
  authenticates the application, not a user, so `WithMtlsProofOfPossession()` is accepted by
  `AcquireTokenByCredential` only (as in MSAL .NET, where it exists only on `AcquireTokenForClient`).
  App tokens are cached automatically, so a repeat `AcquireTokenByCredential` call is a cache hit;
  there is no need to call `AcquireTokenSilent`.
- **Region is optional**: the global `mtlsauth.microsoft.com` endpoint is used when no region is
  configured; a configured region produces `{region}.mtlsauth.microsoft.com`.
- **Transport**: MSAL owns the mTLS transport (it auto-builds and caches an mTLS client per
  certificate thumbprint). A `WithHTTPClient` client's settings reach the mTLS leg only when its
  `Transport` is an `*http.Transport` — that is where proxy, dialer and root CAs live. A custom
  `http.RoundTripper` (a tracing, retry, pinning or request-signing wrapper), or an `*http.Transport`
  that sets `DialTLS`/`DialTLSContext`, cannot carry the binding certificate into the handshake;
  rather than silently rerouting a credential-bearing request onto `http.DefaultTransport`, mTLS
  token requests fail with an error pointing at `WithMtlsHTTPClient`. Redirects are refused on that
  leg unless the `WithHTTPClient` client sets `CheckRedirect`, because a 307 or 308 would replay the
  request body and present the binding certificate to the redirect target.
- **`WithMtlsHTTPClient` is required when the value you pass to `WithHTTPClient` is not an
  `*http.Client`.** `WithHTTPClient` takes an interface (`Do` + `CloseIdleConnections`), but a TLS
  client certificate can only be installed through `*http.Transport`, so any other implementation is
  rejected before the request is sent. It is not an escape hatch for exotic setups: a wrapper type
  that satisfies the interface without being an `*http.Client` reaches this error on the first mTLS
  request. Note that a caller who reaches MSAL through a library that constructs the confidential
  client itself cannot supply either option unless that library forwards them.
- **Sovereign clouds** are supported. `login.microsoftonline.us` (US Gov) and
  `login.partner.microsoftonline.cn` (China) rewrite to `mtlsauth.*` like the public cloud. For the
  mTLS token endpoint the legacy hostnames `login.usgovcloudapi.net` and `login.chinacloudapi.cn` are
  treated as aliases: they resolve to their preferred-network host first, so they reach the same
  endpoint as the modern hostname (`mtlsauth.microsoftonline.us` and
  `mtlsauth.partner.microsoftonline.cn`). This normalization applies to the mTLS token endpoint only.
  Instance discovery does not normalize a legacy alias before regionalizing it, so combining
  `WithAzureRegion` with a legacy alias still produces a regional discovery host built from the
  un-normalized alias — tracked by
  [#654](https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/654). Prefer the
  modern hostname when you configure a region.
- **Authority requirements**: mTLS PoP requires a tenanted AAD or dSTS authority. ADFS is rejected,
  including when it is hosted on a `login.*` host, as are `/common`, `/organizations` and
  `/consumers`. For an AAD authority the `login.*` host must belong to a known Microsoft cloud; a
  private cloud opts in with `WithInstanceDiscovery(false)`, because the derived `mtlsauth.*` host
  receives the binding certificate. Note that `WithInstanceDiscovery(false)` therefore also disables
  this allowlist for every AAD authority, not just a private cloud one. A dSTS authority is not
  rewritten to `mtlsauth.*` — it keeps its resolved token endpoint, so the binding certificate goes
  to the host you configured and no allowlist applies.

### Non-exportable keys (KeyGuard, CNG, HSM)

A key that can't leave its protected store — a Windows KeyGuard (VBS-isolated) key imported with
`PKCS12_VIRTUAL_ISOLATION_KEY`, a CNG key handle, or an HSM-backed key — can only ever be surfaced in
Go as a [`crypto.Signer`](https://pkg.go.dev/crypto#Signer), never as an `*rsa.PrivateKey`. Build the
credential from a `tls.Certificate` holding that signer:

```go
// signer is your crypto.Signer over the non-exportable key (for example one backed by an NCrypt
// key handle); MSAL never sees the private material.
cred, err := confidential.NewCredFromTLSCertificate(tls.Certificate{
    Certificate: chainDER, // DER chain, leaf first
    PrivateKey:  signer,
})
if err != nil {
    // TODO: handle error
}

app, _ := confidential.New("https://login.microsoftonline.com/your_tenant", "client_id", cred)

// works in every flow, e.g. a plain client-credentials call signing a private_key_jwt assertion
result, err := app.AcquireTokenByCredential(context.TODO(),
    []string{"https://vault.azure.net/.default"})

// or bind the token to the certificate with mTLS proof-of-possession
result, err = app.AcquireTokenByCredential(context.TODO(),
    []string{"https://vault.azure.net/.default"},
    confidential.WithMtlsProofOfPossession())
```

Notes:

- **Every flow is supported**: MSAL signs the `client_assertion` through the signer, so
  `private_key_jwt`/SN/I works for client credentials, on-behalf-of, authorization code, refresh
  token, user federated identity credential, and ADFS/dSTS. Two flows send no `client_assertion` at
  all: `WithMtlsProofOfPossession()`, where the key is used solely for the TLS handshake and the token
  is bound to the certificate, and a confidential client's username/password flow, which sends no
  client credential of any kind. The signer's public key must be an `*rsa.PublicKey` to sign an
  assertion, because the service accepts only RSA assertions; a non-RSA signer is limited to mTLS PoP.
- **Assertion signing can fall back to RS256**: assertions are signed PS256 (RSA-PSS). Some providers
  can't do RSA-PSS at all, so if the signer fails MSAL rebuilds the assertion once with RS256 (PKCS#1
  v1.5) and an `x5t` thumbprint, as MSAL .NET does. It's automatic, and it follows any signing failure
  rather than only an unsupported-algorithm one, because `crypto.Signer` gives no portable way to tell
  them apart; a failure RS256 can't fix still fails. An exportable `*rsa.PrivateKey` never falls back.
  MSAL has no logging hook, so a retry that succeeds is otherwise silent — the only signal is the `alg`
  on the wire.
- **No extra transport work is needed**: `crypto/tls` signs the handshake through the signer on both
  TLS 1.2 (PKCS#1 v1.5) and TLS 1.3 (RSA-PSS), so the built-in mTLS transport handles these keys.
  `WithMtlsHTTPClient` remains available if you need to own the handshake for other reasons.
- **The signer lives in your code**: MSAL adds no platform-specific dependencies and ships no signer
  implementation. Implement `crypto.Signer` over your key provider (NCrypt, TPM 2.0, PKCS#11, KMS,
  ...) and hand it to MSAL. Obtaining that signer is the platform-specific part, and it's the part
  MSAL can't do for you: [apps/tests/devapps/keyguard](apps/tests/devapps/keyguard) is a worked
  example — not a supported API — showing a Windows NCrypt `crypto.Signer` over a KeyGuard
  (VBS-isolated) key, along with the steps to provision one.
- `NewCredFromCert` also accepts a `crypto.Signer` whose public key is an `*rsa.PublicKey`.

### Two-leg federated identity credential (FIC) over mTLS PoP

For service-to-service FIC, the application orchestrates two calls, each opting into mTLS PoP. Leg 1
uses the SN/I certificate to obtain a certificate-bound federated assertion; leg 2 presents that
assertion (as a jwt-pop client assertion) together with the binding certificate to obtain the final
`mtls_pop` token:

```go
// Leg 1: SN/I cert -> cert-bound federated assertion (itself mTLS PoP).
leg1, _ := rmaApp.AcquireTokenByCredential(ctx,
    []string{"api://AzureADTokenExchange/.default"},
    confidential.WithMtlsProofOfPossession())

// Leg 2: assertion (jwt-pop) + binding cert -> final mtls_pop token. One callback returns both, so
// they stay paired: leg1.BindingCertificate is a *tls.Certificate carrying the private key, handed
// over without taking it apart.
assertionCred := confidential.NewCredFromSignedAssertionCallback(
    func(context.Context, confidential.AssertionRequestOptions) (confidential.SignedAssertion, error) {
        return confidential.SignedAssertion{
            Assertion:          leg1.AccessToken,
            BindingCertificate: leg1.BindingCertificate,
        }, nil
    })
ficApp, _ := confidential.New(authority, ficClientID, assertionCred)
final, _ := ficApp.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
```

`NewCredFromSignedAssertionCallback` is the only way to supply leg 2's binding certificate, and that
is deliberate: routing the assertion through the credential and the certificate through a separate
call-site option would let the two drift apart across a certificate rotation. MSAL .NET takes the
same position, sourcing the certificate solely from `ClientSignedAssertion.TokenBindingCertificate`.
Running leg 1 inside the callback keeps the pair fresh rather than capturing a single leg-1 result:

```go
cred := confidential.NewCredFromSignedAssertionCallback(
    func(ctx context.Context, _ confidential.AssertionRequestOptions) (confidential.SignedAssertion, error) {
        leg1, err := rmaApp.AcquireTokenByCredential(ctx,
            []string{"api://AzureADTokenExchange/.default"},
            confidential.WithMtlsProofOfPossession())
        if err != nil {
            return confidential.SignedAssertion{}, err
        }
        return confidential.SignedAssertion{
            Assertion:          leg1.AccessToken,
            BindingCertificate: leg1.BindingCertificate,
        }, nil
    })
ficApp, _ := confidential.New(authority, ficClientID, cred)
final, _ := ficApp.AcquireTokenByCredential(ctx, scopes, confidential.WithMtlsProofOfPossession())
```

MSAL invokes the callback at most once per token request. The binding certificate's private key may
be non-exportable (Windows KeyGuard, CNG, an HSM); MSAL only requires that it implement
`crypto.Signer`.

See [docs/federated_managed_identity.md](docs/federated_managed_identity.md) for the full FIC/FMI
walkthrough.

### Bearer tokens over mTLS (no token binding)

`WithSendCertificateOverMtls()` uses the certificate credential to authenticate the *transport*: the
certificate is presented on the mutual-TLS handshake and the request is routed to the `mtlsauth.*`
endpoint. The token that comes back, however, is an **ordinary bearer token**. Unlike
`WithMtlsProofOfPossession()` it is **not** bound to the certificate — `token_type` stays `Bearer`,
there is no `cnf` claim, and it is cached under the normal bearer key.

Use it to replace a client secret with a certificate on the wire when the resource does not need to
understand `mtls_pop`. Nothing changes for the resource.

```go
certs, key, _ := confidential.CertFromPEM(pem, "")
cred, _ := confidential.NewCredFromCert(certs, key)

// App-level: unlike WithMtlsProofOfPossession, this is set at construction rather than per call.
app, _ := confidential.New("https://login.microsoftonline.com/your_tenant", "client_id", cred,
    confidential.WithSendCertificateOverMtls())

result, err := app.AcquireTokenByCredential(context.TODO(),
    []string{"https://vault.azure.net/.default"})
if err != nil {
    // TODO: handle error
}
_ = result.Metadata.TokenType   // "Bearer"
_ = result.BindingCertificate   // nil — the token is not bound to the certificate
```

Notes:

- **Using the token**: send `Authorization: Bearer <token>` over an ordinary TLS connection. Do not
  present a client certificate to the resource; the token carries no binding for it to validate.
- **Which flows**: client credentials, on-behalf-of, authorization code and silent refresh. It is
  not applied to `AcquireTokenByUsernamePassword` (which sends no client credential at all) or
  `AcquireTokenByUserFederatedIdentityCredential`; those two continue to use the regular token
  endpoint. This matches MSAL .NET, whose `SendCertificateOverMtls` covers the same four flows.
- **A per-request `WithMtlsProofOfPossession()` always takes precedence.** Setting both is well
  defined: that call returns a certificate-bound `mtls_pop` token instead. Bound and unbound tokens
  occupy separate cache partitions, so neither is ever served in place of the other.
- **A certificate credential is required**; `New` returns an error for any other kind. That includes
  `NewCredFromSignedAssertionCallback`, even though its callback returns a binding certificate: that
  certificate is produced at request time, and only an mTLS proof-of-possession request resolves the
  callback early enough to present it on the handshake.
- The **authority requirements and transport rules** above apply here too, because the request still
  goes to `mtlsauth.*`: it needs a tenanted AAD authority on a known `login.*` host, and a
  `WithHTTPClient` value that is not an `*http.Client` still requires `WithMtlsHTTPClient`.

## Community Help and Support

We use [Stack Overflow](http://stackoverflow.com/questions/tagged/msal) to work with the community on supporting Azure Active Directory and its SDKs, including this one! We highly recommend you ask your questions on Stack Overflow (we're all on there!) Also browse existing issues to see if someone has had your question before. Please use the "msal" tag when asking your questions.

If you find and bug or have a feature request, please raise the issue on [GitHub Issues](https://github.com/AzureAD/microsoft-authentication-library-for-go/issues).

## Submit Feedback
We'd like your thoughts on this library. Please complete [this short survey.](https://forms.office.com/r/s4waBAytFJ)

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Security Library

This library controls how users sign-in and access services. We recommend you always take the latest version of our library in your app when possible. We use [semantic versioning](http://semver.org) so you can control the risk associated with updating your app. As an example, always downloading the latest minor version number (e.g. x.*y*.x) ensures you get the latest security and feature enhancements but our API surface remains the same. You can always see the latest version and release notes under the Releases tab of GitHub.

## Security Reporting

If you find a security issue with our libraries or services please report it to [secure@microsoft.com](mailto:secure@microsoft.com) with as much detail as possible. Your submission may be eligible for a bounty through the [Microsoft Bounty](http://aka.ms/bugbounty) program. Please do not post security issues to GitHub Issues or any other public site. We will contact you shortly upon receiving the information. We encourage you to get notifications of when security incidents occur by visiting [this page](https://technet.microsoft.com/en-us/security/dd252948) and subscribing to Security Advisory Alerts.

Copyright (c) Microsoft Corporation.  All rights reserved. Licensed under the MIT License (the "License").
