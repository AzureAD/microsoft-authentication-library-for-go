# Managed Identity Public API Design Specification

The purpose of this file is to go over the changes required for adding the Managed Identity feature to MSAL GO

## Public API

The public API will be quite small. Based on the Java and .NET implementations, there is only 1 exposed method, **acquireTokenForManagedIdentity()**

```go
// Acquires tokens from the configured managed identity on an azure resource.
//
// Resource: scopes application is requesting access to
// Options: [WithClaims]
func (client Client) AcquireToken(context context.Context, resource string, options ...AcquireTokenOption) (base.AuthResult, error) {
    return base.AuthResult{}, nil
}

// Source represents the managed identity sources supported.
type Source int

const (
    // AzureArc represents the source to acquire token for managed identity is Azure Arc.
    AzureArc = 0

    // DefaultToIMDS indicates that the source is defaulted to IMDS since no environment variables are set.
    DefaultToIMDS = 1
)

// Detects and returns the managed identity source available on the environment.
func GetSource() Source {
    return DefaultToIMDS
}
```

The end user simply needs to create their own instance of Managed Identity Client, i.e **managedIdentity.Client()**, passing in the **ManagedIdentityType** they want to use, and then call the public API. The example below shows creation of different clients for each of the different Managed Identity Types

```go
import (
    "context"
    "fmt"
    "net/http"

    mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

func RunManagedIdentity() {
    customHttpClient := &http.Client{}

    miSystemAssigned, error := mi.New(mi.SystemAssigned())
    if error != nil {
        fmt.Println(error)
    }

    miClientIdAssigned, error := mi.New(mi.ClientID("client id 123"), mi.WithHTTPClient(customHttpClient))
    if error != nil {
        fmt.Println(error)
    }

    miResourceIdAssigned, error := mi.New(mi.ResourceID("resource id 123"))
    if error != nil {
        fmt.Println(error)
    }

    miObjectIdAssigned, error := mi.New(mi.ObjectID("object id 123"))
    if error != nil {
        fmt.Println(error)
    }

    miSystemAssigned.AcquireToken(context.Background(), "resource", mi.WithClaims("claim"))

    miClientIdAssigned.AcquireToken(context.Background(), "resource")

    miResourceIdAssigned.AcquireToken(context.Background(), "resource", mi.WithClaims("claim"))
    
    miObjectIdAssigned.AcquireToken(context.Background(), "resource")
}
```

To create a new **ManagedIdentityClient**

```go
// Client to be used to acquire tokens for managed identity.
// ID: [SystemAssigned()], [ClientID("clientID")], [ResourceID("resourceID")], [ObjectID("objectID")]
//
// Options: [WithHTTPClient]
func New(id ID, options ...Option) (Client, error) {
    // implementation details
}
```

The options available for passing to the client are  

```go
// WithHTTPClient allows for a custom HTTP client to be set.
func WithHTTPClient(httpClient ops.HTTPClient) Option {
    // implementation details
}

// WithClientCapabilities allows configuring one or more client capabilities such as "CP1"
// that are used to indicate support for features like Continuous Access Evaluation and token revocation.
func WithClientCapabilities(capabilities []string) Option {
    // implementation details
}
```

The options available for the request are 

```go
// WithClaims sets additional claims to request for the token, such as those required by conditional access policies.
// Use this option when Azure AD returned a claims challenge for a prior request. The argument must be decoded.
func WithClaims(claims string) AcquireTokenOption {
    // implementation details
}
```

## Token Revocation Support

The Managed Identity client now supports token revocation in App Service and Service Fabric environments. This feature allows the client to refresh a previously revoked access token using a claims challenge.

The implementation follows these steps:
1. The client detects a token revocation scenario when a claims challenge is provided in the `WithClaims` option
2. When a claims challenge is provided and a cached token exists, the client calculates the SHA256 hash of the cached token
3. The token hash is sent in the request as the `token_sha256_to_refresh` parameter
4. Client capabilities are sent in the request as the `xms_cc` parameter if they were configured with `WithClientCapabilities`

Example usage:

```go
// Create client with token revocation support
client, err := mi.New(
    mi.SystemAssigned(), 
    mi.WithClientCapabilities([]string{"CP1"}),
)

// Get a token normally
result, err := client.AcquireToken(context.Background(), "resource")

// When a token revocation is detected, use WithClaims to pass the claims challenge
claims := `{"access_token":{"xms_cc":{"values":["CP1"]}}}`
result, err = client.AcquireToken(
    context.Background(), 
    "resource",
    mi.WithClaims(claims),
)
```

## Error Handling

Error handling in GO is different to what we used to in languages like Java or Swift.
There is no concept of ‘exceptions’, instead we just return errors and immediately check if an error was returned and handle it there and then.  
The SDK will return client-side errors like so:

```go
if err != nil {
    return errors.New("Some Managed Identity Error here”) 
}
```

This will be inside of any client methods that throw errors, using descriptive errors based on the .NET and Java Implementation. These errors will be propagated down the chain and handled when they are received

For service side errors it works a little differently

```go
switch reply.StatusCode { 
    case 200, 201: 
    default: 
        sd := strings.TrimSpace(string(data)) 

        if sd != "" { 
            // We probably have the error in the body. 
            return nil, errors.CallErr { 
                Req: req, 
                Resp: reply, 
                Err: fmt.Errorf("http call(%s)(%s) error: reply status code was %d:\n%s",req.URL.String(), req.Method, reply.StatusCode, sd)
            } 
        }  

        return nil, errors.CallErr{ 
            Req: req, 
            Resp: reply, 
            Err: fmt.Errorf("http call(%s)(%s) error: reply status code was %d", req.URL.String(), req.Method, reply.StatusCode), 
 } 
}
```

In this example, you can see we are returning **errors.CallErr(Req: httpRequest, Resp: httpResponse, Err: error)**

For the service side errors we have a struct object like this:

```go
type CallErr struct { 
    Req *http.Request 
    // Resp contains response body 
    Resp *http.Response 
    Err error 
} 
```

This structure should be followed for future service calls. More information on this implementation can be found [here](https://github.com/AzureAD/microsoft-authentication-library-for-go/blob/ae2db6b72c7010958355f448e99209bd28e76e67/apps/errors/error_design.md#L1)

## Caching

Other MSALs have an Enum called **TokenSource** that lets us differentiate between **IdentityProvider**, **Cache** and **Broker**.  

Since GO does not have Brokers, we have created a PR [here](https://github.com/AzureAD/microsoft-authentication-library-for-go/pull/498) that adds a **AuthenticationResultMetadata** class to the **_base.go_** instance of **AuthResult**  

This **AuthenticationResultMetadata** contains the **TokenSource** and **RefreshOn** values, like .NET and Java implementations. The **TokenSource** here does not contain the broker field as it is not something that is planned currently

```go
type TokenSource int

const (
    IdentityProvider TokenSource = 0
    Cache = 1
)

type AuthResultMetadata struct {
    TokenSource TokenSource
    RefreshOn time.Time
}
```

## FIC Support

You can review information on FIC [here](https://review.learn.microsoft.com/en-us/identity/microsoft-identity-platform/federated-identity-credentials?branch=main&tabs=dotnet)

Managed Identity abstracts the complexity of certificates away, by virtue of being hosted on an Azure VM you get access to the services you need i.e. key vault

Managed Identity is a single tenant. This is an issue as Microsoft has many multi tenanted apps.
FIC solves this by allowing you to declare a trust relationship with an identity provider and application i.e. ‘I trust this GitHub token, if I see this Git Hub token, give me a token for something I want access to i.e. Key Vault’
So, if you can get a token for Managed Identity you can use it to access the key vault in all tenants

Right now, we shouldn’t have to do anything.
Currently FIC would be the token for the certificate in **acquireTokenByCredential()**, we would just provide the token for ManagedIdentity instead of using the certificate

This is a 2-step process:

1. Get token for Managed Identity. Would be a special token for a specific scope.  

2. Create a confidential client and get a token. Will get an API certificate for the assertion, and use the Managed Identity token instead of the certificate  

All we need to do for now is test FIC with Managed Identity, and update any documentation to go along with it