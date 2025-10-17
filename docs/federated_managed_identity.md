# Federated Managed Identity (FMI)

## Overview

Federated Managed Identity (FMI) enables Azure services to use federated credentials for authentication via an assertion callback. The FMI credential is typically obtained from a Resource Management API (RMA) service and used with the special client ID `urn:microsoft:identity:fmi`.

## Key Features

- **Assertion-Based Authentication**: Uses callback functions to dynamically retrieve FMI credentials
- **Cache Isolation**: Tokens acquired with different FMI paths are cached separately
- **FMI Path Support**: The `WithFMIPath` option identifies the specific federated credential path

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

}
```

## Cache Behavior

Tokens acquired with FMI are **automatically isolated** in the cache. This means:

- Tokens with different FMI paths are cached separately
- FMI tokens don't interfere with regular (non-FMI) tokens
- Silent token acquisition works seamlessly with cached FMI tokens

```go
// First call - acquires from identity provider
result, err := app.AcquireTokenByCredential(ctx, scopes,
    confidential.WithFMIPath("YourFmiPath/CredentialPath"))

// Second call - retrieves from cache automatically
cachedResult, err := app.AcquireTokenSilent(ctx, scopes)
```

## How It Works

1. **Assertion Callback**: Your callback function retrieves an FMI credential from RMA
2. **FMI Path**: The `WithFMIPath` option identifies the specific federated credential
3. **Automatic Isolation**: MSAL handles cache isolation transparently based on the FMI path
4. **Token Retrieval**: Silent authentication automatically finds the correct cached token

## Important Notes

- Use the special client ID `urn:microsoft:identity:fmi` for FMI scenarios
- The FMI credential is typically obtained from an RMA (Resource Management API) service  
- Cache isolation is handled automatically - no manual cache management needed


