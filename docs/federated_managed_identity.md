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

## mTLS Proof-of-Possession (both legs)

The two-leg flow above returns Bearer tokens by default. To bind the tokens to the SN/I certificate
over mutual TLS, opt into mTLS proof-of-possession on **each** leg. The credential is unchanged — only
the mechanism changes from signing an assertion to presenting the certificate as the client TLS
certificate. Both legs return `token_type=mtls_pop`.

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
// certificate is presented on the TLS handshake. Supply it with WithMtlsBindingTLSCertificate,
// which takes leg 1's result as-is, because the leg-2 credential is an assertion callback that has
// no certificate of its own.
result, err := app.AcquireTokenByCredential(
    ctx,
    []string{"your-resource/.default"},
    confidential.WithFMIPath("YourFmiPath/CredentialPath"),
    confidential.WithMtlsProofOfPossession(
        confidential.WithMtlsBindingTLSCertificate(leg1.BindingCertificate)),
)
// result.Metadata.TokenType == "mtls_pop", bound to the leg-1 certificate thumbprint.
```

### Keeping the assertion and its binding certificate together

Passing the assertion through the credential and the certificate through an option lets the two drift
apart — a certificate rotation between leg 1 and leg 2 can pair one leg's assertion with another
leg's certificate. `NewCredFromSignedAssertionCallback` closes that gap: one callback returns both,
so they are always the pair leg 1 produced.

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
// No binding-certificate option needed: the credential supplies it with the assertion.
result, err := app.AcquireTokenByCredential(
    ctx,
    []string{"your-resource/.default"},
    confidential.WithFMIPath("YourFmiPath/CredentialPath"),
    confidential.WithMtlsProofOfPossession(),
)
```

MSAL invokes the callback at most once per token request. Because the binding certificate partitions
the token cache and selects the mutual-TLS connection, an mTLS PoP request resolves the callback
before the cache is consulted; requests that don't need the certificate invoke it only when a token
request is actually sent, exactly like `NewCredFromAssertionCallback`.

Notes:

- A **tenanted authority** is required (not `/common`, `/organizations`, or `/consumers`).
- The token endpoint is rewritten from `login.*` to `mtlsauth.*`; region is optional (global
  `mtlsauth.microsoft.com` is used when no region is configured).
- A binding certificate is only needed on the assertion-authenticated leg (leg 2). For a leg
  created with `NewCredFromCert` (leg 1) it is inferred from the credential. Supply it with
  `WithMtlsBindingTLSCertificate` (a `*tls.Certificate`, what leg 1 returns),
  `WithMtlsBindingCertificate` (a chain plus a private key), or `NewCredFromSignedAssertionCallback`.
  An explicitly passed certificate takes precedence over one from the callback.
- Results expose the binding certificate as `BindingCertificate` (a `*tls.Certificate` carrying the
  parsed leaf and the private key, ready for `tls.Config.Certificates`) and its thumbprint as
  `BindingCertificateThumbprint()`.
- The private key may be non-exportable (Windows KeyGuard, CNG, an HSM); MSAL only requires that it
  implement `crypto.Signer`.
- Sovereign clouds are supported via `login.microsoftonline.us` (US Gov) and
  `login.partner.microsoftonline.cn` (China); the legacy hosts `login.usgovcloudapi.net` and
  `login.chinacloudapi.cn` are rejected with guidance toward the supported host.

## Cache Behavior

Tokens acquired with FMI are **automatically isolated** in the cache. This means:

- Tokens with different FMI paths are cached separately
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
- Cache isolation is handled automatically - no manual cache management needed


