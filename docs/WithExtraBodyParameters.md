# WithExtraBodyParameters API Documentation

## Overview

The `WithExtraBodyParameters` API allows developers to add custom body parameters to token requests in MSAL Go. This feature is particularly useful for scenarios where additional parameters need to be sent to the authorization server, such as custom authentication requirements or special token attributes.

## Key Features

1. **Dynamic Parameter Evaluation**: Parameters are provided as functions that are evaluated at request time, allowing for dynamic values that may change between requests.

2. **Cache Key Association**: Extra body parameters are automatically included in the cache key, ensuring that tokens acquired with different parameters are cached separately.

3. **Context Support**: Parameter functions receive the request context, enabling access to context values and proper cancellation support.

## Usage

### Basic Example

```go
package main

import (
    "context"
    "fmt"
    "github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

func main() {
    // Create confidential client
    cred, err := confidential.NewCredFromSecret("your-client-secret")
    if err != nil {
        panic(err)
    }

    app, err := confidential.New(
        "https://login.microsoftonline.com/your-tenant-id",
        "your-client-id",
        cred,
    )
    if err != nil {
        panic(err)
    }

    // Define extra body parameters
    extraParams := map[string]func(context.Context) (string, error){
        "custom_param": func(ctx context.Context) (string, error) {
            return "custom_value", nil
        },
    }

    // Acquire token with extra parameters
    result, err := app.AcquireTokenByCredential(
        context.Background(),
        []string{"https://graph.microsoft.com/.default"},
        confidential.WithExtraBodyParameters(extraParams),
    )
    if err != nil {
        panic(err)
    }

    fmt.Println("Access token:", result.AccessToken)
}
```

### Advanced Example: Dynamic Values

```go
// Use dynamic parameter values that change on each request
extraParams := map[string]func(context.Context) (string, error){
    "timestamp": func(ctx context.Context) (string, error) {
        return fmt.Sprintf("%d", time.Now().Unix()), nil
    },
    "request_id": func(ctx context.Context) (string, error) {
        return uuid.New().String(), nil
    },
}

result, err := app.AcquireTokenByCredential(
    ctx,
    scopes,
    confidential.WithExtraBodyParameters(extraParams),
)
```

### Example: Using Context Values

```go
type contextKey string

const userIDKey = contextKey("user_id")

// Set a value in context
ctx := context.WithValue(context.Background(), userIDKey, "user123")

// Access context value in parameter function
extraParams := map[string]func(context.Context) (string, error){
    "user_context": func(ctx context.Context) (string, error) {
        userID := ctx.Value(userIDKey)
        if userID == nil {
            return "", errors.New("user ID not found in context")
        }
        return userID.(string), nil
    },
}

result, err := app.AcquireTokenByCredential(
    ctx,
    scopes,
    confidential.WithExtraBodyParameters(extraParams),
)
```

### Example: Error Handling

```go
extraParams := map[string]func(context.Context) (string, error){
    "external_param": func(ctx context.Context) (string, error) {
        // Fetch value from external service
        value, err := fetchFromExternalService(ctx)
        if err != nil {
            return "", fmt.Errorf("failed to fetch parameter value: %w", err)
        }
        return value, nil
    },
}

result, err := app.AcquireTokenByCredential(
    ctx,
    scopes,
    confidential.WithExtraBodyParameters(extraParams),
)
if err != nil {
    // Handle errors from parameter evaluation or token acquisition
    log.Printf("Token acquisition failed: %v", err)
}
```

## Caching Behavior

Tokens acquired with different extra body parameters are cached separately. This ensures that:

1. **Cache Isolation**: Tokens with different parameters don't interfere with each other
2. **Correct Token Retrieval**: Subsequent requests with the same parameters will retrieve the correct cached token
3. **Parameter-Based Cache Keys**: The cache key includes a hash of the parameter names

### Example: Cache Key Behavior

```go
// First request with param1
params1 := map[string]func(context.Context) (string, error){
    "custom_param": func(ctx context.Context) (string, error) {
        return "value1", nil
    },
}
result1, _ := app.AcquireTokenByCredential(ctx, scopes,
    confidential.WithExtraBodyParameters(params1))
// This makes a network request and caches the token with param1

// Second request with different param
params2 := map[string]func(context.Context) (string, error){
    "different_param": func(ctx context.Context) (string, error) {
        return "value2", nil
    },
}
result2, _ := app.AcquireTokenByCredential(ctx, scopes,
    confidential.WithExtraBodyParameters(params2))
// This makes a network request and caches a different token with param2

// Third request with param1 again
result3, _ := app.AcquireTokenByCredential(ctx, scopes,
    confidential.WithExtraBodyParameters(params1))
// This retrieves result1 from cache (no network request)
```

## API Reference

### Function Signature

```go
func WithExtraBodyParameters(
    params map[string]func(context.Context) (string, error),
) interface{ AcquireByCredentialOption }
```

### Parameters

- `params`: A map where:
  - **Key** (string): The parameter name to be added to the token request body
  - **Value** (function): A function that:
    - Takes a `context.Context` as input
    - Returns a `(string, error)` tuple
    - Is evaluated at request time to get the parameter value

### Return Value

Returns an option that can be passed to `AcquireTokenByCredential`.

### Supported Methods

Currently, `WithExtraBodyParameters` is supported for:

- `AcquireTokenByCredential` (Confidential Client)

## Implementation Details

### Parameter Evaluation

1. Parameter functions are called at request time, just before the token request is made
2. If any parameter function returns an error, the entire token acquisition fails
3. `nil` parameter functions are skipped (no parameter is added)
4. The context passed to parameter functions is the same context passed to `AcquireTokenByCredential`

### Cache Key Generation

The cache key includes:
1. Client ID
2. Tenant ID
3. A hash of the extra body parameter **names** (not values)

This ensures that:
- Different parameter sets are cached separately
- The same parameter set (even with different values) uses the same cache key
- Cache lookups are efficient and predictable

### Thread Safety

- Parameter functions should be thread-safe if the client is used concurrently
- Parameter functions may be called multiple times (on cache miss or refresh)
- Do not rely on side effects in parameter functions

## Best Practices

### 1. Keep Parameter Functions Simple

```go
// Good: Simple, fast function
extraParams := map[string]func(context.Context) (string, error){
    "client_version": func(ctx context.Context) (string, error) {
        return "1.0.0", nil
    },
}

// Avoid: Expensive operations without caching
extraParams := map[string]func(context.Context) (string, error){
    "expensive_param": func(ctx context.Context) (string, error) {
        // This will be called on every token request!
        return expensiveComputation()
    },
}
```

### 2. Handle Errors Gracefully

```go
extraParams := map[string]func(context.Context) (string, error){
    "config_value": func(ctx context.Context) (string, error) {
        value, err := loadConfig()
        if err != nil {
            return "", fmt.Errorf("failed to load config: %w", err)
        }
        if value == "" {
            return "", errors.New("config value is empty")
        }
        return value, nil
    },
}
```

### 3. Respect Context Cancellation

```go
extraParams := map[string]func(context.Context) (string, error){
    "external_data": func(ctx context.Context) (string, error) {
        // Check if context is cancelled
        select {
        case <-ctx.Done():
            return "", ctx.Err()
        default:
        }

        // Use context in external calls
        return fetchDataWithContext(ctx)
    },
}
```

### 4. Use Consistent Parameter Names

```go
// Good: Consistent parameter names for related requests
params1 := map[string]func(context.Context) (string, error){
    "resource_id": func(ctx context.Context) (string, error) {
        return "resource1", nil
    },
}

params2 := map[string]func(context.Context) (string, error){
    "resource_id": func(ctx context.Context) (string, error) {
        return "resource2", nil
    },
}
// These will use the same cache key structure
```

## Limitations

1. **Confidential Client Only**: Currently only supported for `AcquireTokenByCredential` in confidential clients
2. **Parameter Names Only in Cache Key**: The cache key is based on parameter names, not values. Different values for the same parameter name will use the same cache entry.
3. **No Parameter Validation**: MSAL Go does not validate parameter names or values. The authorization server will return an error for invalid parameters.

## Comparison with MSAL .NET

This implementation is based on MSAL .NET PR #5389 and maintains feature parity:

| Feature | MSAL .NET | MSAL Go |
|---------|-----------|---------|
| Dynamic parameter values | ✅ `Func<CancellationToken, Task<string>>` | ✅ `func(context.Context) (string, error)` |
| Cache key association | ✅ Yes | ✅ Yes |
| Context/Cancellation support | ✅ CancellationToken | ✅ context.Context |
| Confidential client support | ✅ Yes | ✅ Yes |
| Public client support | ❌ N/A | ❌ N/A |

## Troubleshooting

### Issue: Parameter function not being called

**Problem**: Your parameter function is not being executed.

**Solution**:
- Ensure you're passing the option to `AcquireTokenByCredential`
- Check that the parameter function is not `nil`
- Verify that the token is not being served from cache (parameter functions are only called on cache miss)

### Issue: Different tokens expected but getting cached token

**Problem**: You're getting a cached token when you expected a new token with different parameter values.

**Solution**:
- The cache key is based on parameter **names**, not values
- If you need different cache entries, use different parameter names
- Alternatively, use different clients or clear the cache

### Issue: Parameter function returns error

**Problem**: Token acquisition fails with an error from your parameter function.

**Solution**:
- Add proper error handling in your parameter function
- Log errors for debugging
- Ensure external dependencies are available and responding

## See Also

- [MSAL Go Confidential Client Documentation](../apps/confidential/)
- [MSAL .NET PR #5389](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/pull/5389)
- [Microsoft Identity Platform Documentation](https://docs.microsoft.com/azure/active-directory/develop/)
