# Federated Managed Identity (FMI)

## Overview

Federated Managed Identity (FMI) enables Azure services to use federated credentials for authentication via an assertion callback. The FMI credential is typically obtained from a Resource Management API (RMA) service and used with the special client ID `urn:microsoft:identity:fmi`.

## Key Features

- **Assertion-Based Authentication**: Uses callback functions to dynamically retrieve FMI credentials
- **Cache Isolation**: Tokens acquired with different FMI paths are cached separately
- **FMI Path Support**: The `WithFMIPath` option identifies the specific federated credential path
- **Attribute Support**: The `WithAttribute` option allows passing additional attributes in token requests

## Basic Usage

### Step 1: Create an FMI Credential Provider

```go
import (
    "context"
    "github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// GetFMICredentialFromRMA acquires an FMI token from the RMA service
func GetFMICredentialFromRMA(ctx context.Context) (string, error) {
    // Get your certificate for authenticating to RMA
    cert, privateKey, err := getCertificateData()
    if err != nil {
        return "", err
    }

    // Create credential from certificate
    cred, err := confidential.NewCredFromCert(cert, privateKey)
    if err != nil {
        return "", err
    }

    // Create client for RMA service
    rmaClient, err := confidential.New(
        "https://login.microsoftonline.com/tenant-id",
        "your-rma-client-id",
        cred,
    )
    if err != nil {
        return "", err
    }

    // Acquire FMI token from RMA with FMI path
    result, err := rmaClient.AcquireTokenByCredential(
        ctx,
        []string{"api://AzureFMITokenExchange/.default"},
        confidential.WithFMIPath("YourFmiPath/CredentialPath"),
    )
    if err != nil {
        return "", err
    }

    return result.AccessToken, nil
}
```

### Step 2: Use FMI with Assertion Callback

```go
func main() {
    ctx := context.Background()

    // Create FMI credential using assertion callback
    fmiCred := confidential.NewCredFromAssertionCallback(
        func(ctx context.Context, aro confidential.AssertionRequestOptions) (string, error) {
            return GetFMICredentialFromRMA(ctx)
        },
    )

    // Create confidential client with FMI client ID
    app, err := confidential.New(
        "https://login.microsoftonline.com/tenant-id",
        "urn:microsoft:identity:fmi",  // Special FMI client ID
        fmiCred,
        confidential.WithCache(cacheAccessor),
    )
    if err != nil {
        panic(err)
    }

    // Acquire token using FMI
    result, err := app.AcquireTokenByCredential(
        ctx,
        []string{"your-resource/.default"},
        confidential.WithFMIPath("YourFmiPath/CredentialPath"),
    )
    if err != nil {
        panic(err)
    }

    // Use the access token
    accessToken := result.AccessToken
}
```

### Step 3: Using in-line attributes
```go
    ctx := context.Background()

    app, err := confidential.New(
        "https://login.microsoftonline.com/tenant-id",
        "urn:microsoft:identity:fmi",  // Special FMI client ID
        fmiCred,
    )
    if err != nil {
        panic(err)
    }
    result, err := app.AcquireTokenByCredential(
        ctx,
        []string{"your-resource/.default"},
        confidential.WithFMIPath("YourFmiPath/CredentialPath"),
        confidential.WithAttribute("your-attribute-value"), // Optional attribute
    )
}
```

## Certificate-bound two-leg FIC over mTLS

Use mTLS proof-of-possession on leg 1 to obtain the certificate-bound federated assertion. On leg 2,
return that assertion and certificate together from `NewCredFromSignedAssertionCallback`. Certificate
presence keeps the assertion `jwt-pop` and presents the same certificate over mTLS regardless of the
final token type:

- Without `WithMtlsProofOfPossession()`, leg 2 sends no `token_type=mtls_pop` or `req_cnf`, requires
  a normal `Bearer` response, caches it under the normal Bearer key, and returns no
  `BindingCertificate`.
- With `WithMtlsProofOfPossession()`, leg 2 requests and requires `token_type=mtls_pop`, partitions
  the cache by the binding certificate, and returns that certificate with the result.

```go
// Leg 1 (inside your RMA helper): SN/I cert -> cert-bound federated assertion, itself mTLS PoP.
// The exchange audience is caller-supplied: api://AzureADTokenExchange for generic S2S FIC, or
// api://AzureFMITokenExchange (+ WithFMIPath) for the FMI variant.
leg1, err := rmaClient.AcquireTokenByCredential(
    ctx,
    []string{"api://AzureFMITokenExchange/.default"},
    confidential.WithFMIPath("YourFmiPath/CredentialPath"),
    confidential.WithMtlsProofOfPossession(),
)
// leg1.Metadata.TokenType == "mtls_pop"; leg1.BindingCertificate is a *tls.Certificate carrying the
// parsed leaf and the private key (which may be a non-exportable crypto.Signer).

// Leg 2: the federated assertion is presented as a jwt-pop client assertion, and the same binding
// certificate is presented on the TLS handshake. Because the leg-2 credential is an assertion that
// has no certificate of its own, use NewCredFromSignedAssertionCallback: one callback returns leg 1's
// assertion and the certificate it is bound to, so the two can never drift apart. There is no
// call-site option for the certificate — see below.
cred := confidential.NewCredFromSignedAssertionCallback(
    func(ctx context.Context, _ confidential.AssertionRequestOptions) (confidential.SignedAssertion, error) {
        return confidential.SignedAssertion{
            Assertion:          leg1.AccessToken,
            BindingCertificate: leg1.BindingCertificate,
        }, nil
    })

app, err := confidential.New(authority, clientID, cred)

bearer, err := app.AcquireTokenByCredential(
    ctx,
    []string{"your-resource/.default"},
    confidential.WithFMIPath("YourFmiPath/CredentialPath"),
)
// bearer.Metadata.TokenType == "Bearer"; bearer.BindingCertificate == nil.

pop, err := app.AcquireTokenByCredential(
    ctx,
    []string{"your-resource/.default"},
    confidential.WithFMIPath("YourFmiPath/CredentialPath"),
    confidential.WithMtlsProofOfPossession(),
)
// pop.Metadata.TokenType == "mtls_pop", bound to the leg-1 certificate thumbprint.
```

### Keeping the assertion and its binding certificate together

Pairing the assertion and the certificate in one callback is the only supported form, and that is
deliberate. Passing the assertion through the credential and the certificate through a separate
call-site option would let the two drift apart — a certificate rotation between leg 1 and leg 2 could
pair one leg's assertion with another leg's certificate. MSAL .NET takes the same position: the
certificate comes solely from `ClientSignedAssertion.TokenBindingCertificate`, returned by the
`WithClientAssertion` callback.

Running leg 1 inside the callback keeps the pair fresh, rather than capturing a single leg-1 result:

```go
cred := confidential.NewCredFromSignedAssertionCallback(
    func(ctx context.Context, _ confidential.AssertionRequestOptions) (confidential.SignedAssertion, error) {
        leg1, err := rmaClient.AcquireTokenByCredential(
            ctx,
            []string{"api://AzureFMITokenExchange/.default"},
            confidential.WithFMIPath("YourFmiPath/CredentialPath"),
            confidential.WithMtlsProofOfPossession(),
        )
        if err != nil {
            return confidential.SignedAssertion{}, err
        }
        return confidential.SignedAssertion{
            Assertion:          leg1.AccessToken,
            BindingCertificate: leg1.BindingCertificate,
        }, nil
    })

app, err := confidential.New(authority, clientID, cred)
// No binding-certificate option is needed: the credential supplies it with the assertion.
// Add WithMtlsProofOfPossession() only when the final token must also be certificate-bound.
result, err := app.AcquireTokenByCredential(ctx, []string{"your-resource/.default"})
```

MSAL invokes the callback exactly once per supported confidential-client acquisition, including
cache hits, to create one immutable assertion/certificate snapshot. The snapshot selects the TLS
connection and assertion type before cache lookup. A final Bearer token uses the normal Bearer cache
entry; an `mtls_pop` token uses a separate token-type entry partitioned by certificate.

Notes:

- A **tenanted authority** is required (not `/common`, `/organizations`, or `/consumers`).
- The token endpoint is rewritten from `login.*` to `mtlsauth.*`; region is optional (global
  `mtlsauth.microsoft.com` is used when no region is configured).
- For a leg created with `NewCredFromCert` (leg 1), the certificate is inferred from the credential.
  For the assertion-authenticated leg it comes only from
  `SignedAssertion.BindingCertificate`; MSAL exposes no call-site option that could source the
  assertion and certificate independently.
- Only `mtls_pop` results expose the binding certificate as `BindingCertificate` (a
  `*tls.Certificate` carrying the parsed leaf and private key, ready for
  `tls.Config.GetClientCertificate`) and its thumbprint as `BindingCertificateThumbprint()`. A final
  Bearer result deliberately exposes neither capability.
- The private key may be non-exportable (Windows KeyGuard, CNG, an HSM); MSAL only requires that it
  implement `crypto.Signer`.
- Sovereign clouds are supported via `login.microsoftonline.us` (US Gov) and
  `login.partner.microsoftonline.cn` (China); the legacy hosts `login.usgovcloudapi.net` and
  `login.chinacloudapi.cn` are treated as aliases, resolving to their preferred-network host first so
  they reach the same mTLS endpoint as the modern hostname.

## Cache Behavior

Tokens acquired with FMI are **automatically isolated** in the cache. This means:

- Tokens with different FMI paths are cached separately
- Exact `WithAttribute` strings participate in cache identity with or without FMI; different values are cached separately
- FMI tokens don't interfere with regular (non-FMI) tokens
- Silent token acquisition works seamlessly with cached FMI tokens

```go
// First call - acquires from identity provider
result, err := app.AcquireTokenByCredential(ctx, scopes,
    confidential.WithFMIPath("YourFmiPath/CredentialPath"))

// Second call - retrieves from cache
cachedResult, err := app.AcquireTokenByCredential(ctx, scopes, 
    confidential.WithFMIPath("YourFmiPath/CredentialPath"))
```

## How It Works

1. **Assertion Callback**: Your callback function retrieves an FMI credential from RMA
2. **FMI Path**: The `WithFMIPath` option identifies the specific federated credential
3. **Automatic Isolation**: MSAL handles cache isolation transparently based on the FMI path
4. **Token Retrieval**: Silent authentication automatically finds the correct cached token
5. **withAttribute**: You can pass additional attributes using the `WithAttribute` option, which will be included in the token request to the identity provider.

## Important Notes

- Use the special client ID `urn:microsoft:identity:fmi` for FMI scenarios
- The FMI credential is typically obtained from an RMA (Resource Management API) service  
- Cache isolation is handled automatically for new cache entries; no manual cache management is needed during normal operation.
- On upgrade, purge or rotate affected caches and recreate clients; the fix does not clean up legacy entries. Do not share a cache namespace between affected and fixed versions.
