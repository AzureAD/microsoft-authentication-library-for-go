# Microsoft Authentication Library (MSAL) for Go

**MSAL for Go is a new addition to the MSAL family of libraries, has been made available in production ready preview to gauge customer interest and to gather feedback from the community. We welcome all contributors (see [CONTRIBUTING.md](https://github.com/AzureAD/microsoft-authentication-library-for-go/blob/dev/CONTRIBUTING.md)) to help us grow our list of supported MSAL SDKs.**

The Microsoft Authentication Library (MSAL) for Go is part of the [Microsoft identity platform for developers](https://aka.ms/aaddevv2) (formerly named Azure AD) v2.0. It allows you to sign in users or apps with Microsoft identities ([Azure AD](https://azure.microsoft.com/services/active-directory/) and [Microsoft Accounts](https://account.microsoft.com)) and obtain tokens to call Microsoft APIs such as [Microsoft Graph](https://graph.microsoft.io/) or your own APIs registered with the Microsoft identity platform. It is built using industry standard OAuth2 and OpenID Connect protocols.

The latest code resides in the `dev` branch.

Quick links:

| [Getting Started](https://docs.microsoft.com/azure/active-directory/develop/#quickstarts) | [GoDoc](https://pkg.go.dev/github.com/AzureAD/microsoft-authentication-library-for-go/apps) | [Wiki](https://github.com/AzureAD/microsoft-authentication-library-for-go/wiki) | [Samples](https://github.com/AzureAD/microsoft-authentication-library-for-go/tree/dev/apps/tests/devapps) | [Support](README.md#community-help-and-support) | [Feedback](https://forms.office.com/r/s4waBAytFJ) | 
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

### Public Surface

The Public API of the library can be found in the following directories under `apps`.

```
apps/ - Contains all our code
  confidential/ - The confidential application API
  public/ - The public application API
  cache/ - The cache interface that can be implemented to provide persistence cache storage of credentials
```

Acquiring tokens with MSAL Go follows this general three step pattern. There might be some slight differences for other token acquisition flows. Here is a basic example:

1. MSAL separates [public and confidential client applications](https://tools.ietf.org/html/rfc6749#section-2.1). So, you would create an instance of a `PublicClientApplication` and `ConfidentialClientApplication` and use this throughout the lifetime of your application.
   * Initializing a public client:

    ```go
    publicClientApp, err := public.New("client_id", public.WithAuthority("https://login.microsoft.com/Enter_The_Tenant_Name_Here"))
    ```

   * Initializing a confidential client:

    ```go
    // Initializing the client credential
    cred, err := confidential.NewCredFromSecret("client_secret")
    if err != nil {
        return nil, fmt.Errorf("could not create a cred from a secret: %w", err)
    }
    confidentialClientApp, err := confidential.New("client_id", cred, confidential.WithAuthority("https://login.microsoft.com/Enter_The_Tenant_Name_Here"))
    ```

1. MSAL comes packaged with an in-memory cache. Utilizing the cache is optional, but we would highly recommend it.

    ```go
    var userAccount public.Account
    accounts := publicClientApp.Accounts()
    if len(accounts) > 0 {
        // Assuming the user wanted the first account
        userAccount = accounts[0]
        // found a cached account, now see if an applicable token has been cached
        result, err := publicClientApp.AcquireTokenSilent(context.Background(), []string{"your_scope"}, public.WithSilentAccount(userAccount))
        accessToken := result.AccessToken
    }
    ```

1. If there is no suitable token in the cache, or you choose to skip this step, now we can send a request to AAD to obtain a token.

    ```go
    result, err := publicClientApp.AcquireToken"ByOneofTheActualMethods"([]string{"your_scope"}, ...(other parameters depending on the function))
    if err != nil {
        log.Fatal(err)
    }
    accessToken := result.AccessToken
    ```

You can view the [dev apps](https://github.com/AzureAD/microsoft-authentication-library-for-go/tree/dev/apps/tests/devapps) on how to use MSAL Go with various application types in various scenarios. For more detailed information, please refer to the [wiki](https://github.com/AzureAD/microsoft-authentication-library-for-go/wiki).

# Releases
The list of [releases](https://github.com/AzureAD/microsoft-authentication-library-for-go/releases)

## Roadmap

This is a preview library. Details of the roadmap will come soon in the [wiki pages](https://github.com/AzureAD/microsoft-authentication-library-for-go/wiki), along with release notes.

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
