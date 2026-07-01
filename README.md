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
_ = result.BindingCertificate                  // public binding certificate (never the private key)
_ = result.BindingCertificateThumbprint()      // base64url SHA-256 (x5t#S256)
```

Notes:

- **Binding is via the TLS certificate**: no `client_assertion` and no `req_cnf` are sent for a
  pure-certificate request. The endpoint is rewritten from `login.*` to `mtlsauth.*`.
- **Region is optional**: the global `mtlsauth.microsoft.com` endpoint is used when no region is
  configured; a configured region produces `{region}.mtlsauth.microsoft.com`.
- **Transport**: MSAL owns the mTLS transport (it auto-builds and caches an mTLS client per
  certificate thumbprint). A plain `WithHTTPClient` cannot carry the certificate; use
  `WithMtlsHTTPClient` to override the transport for keys the built-in transport can't use.
- **Not supported** on US Gov / China sovereign clouds today.

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

// Leg 2: assertion (jwt-pop) + binding cert -> final mtls_pop token.
assertionCred := confidential.NewCredFromAssertionCallback(
    func(context.Context, confidential.AssertionRequestOptions) (string, error) {
        return leg1.AccessToken, nil
    })
ficApp, _ := confidential.New(authority, ficClientID, assertionCred)
final, _ := ficApp.AcquireTokenByCredential(ctx, scopes,
    confidential.WithMtlsProofOfPossession(confidential.WithMtlsBindingCertificate(certs, key)))
```

See [docs/federated_managed_identity.md](docs/federated_managed_identity.md) for the full FIC/FMI
walkthrough.

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
