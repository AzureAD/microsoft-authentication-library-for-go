# Microsoft Authentication Library (MSAL) for Go

The MSAL library for Go is part of the [Microsoft identity platform for developers](https://aka.ms/aaddevv2) (formerly named Azure AD) v2.0. It enables you to acquire security tokens to call protected APIs. It uses industry standard OAuth2 and OpenID Connect. The library also supports [Azure AD B2C](https://azure.microsoft.com/services/active-directory-b2c/).

Quick links:

| [Conceptual documentation](https://aka.ms/msalnet) | [Getting Started](https://docs.microsoft.com/azure/active-directory/develop/#quickstarts) | [Sample Code](https://aka.ms/aaddevsamplesv2) | [Library Reference](https://docs.microsoft.com/dotnet/api/microsoft.identity.client?view=azure-go) | [Support](README.md#community-help-and-support) |
| ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------- |

## packages

Released     | Nightly
-----------------------------|-------------------------
TBD 

## Build Status
 
TBD

## Release notes, roadmap and SLA

### Release notes and roadmap

MSAL Go roadmap is available from [Roadmap](../../wiki#roadmap) in the [Wiki pages](https://aka.ms/msal-go), along with release notes.

### Support SLA

MSAL Go is in early development

- Major versions are supported for twelve months after the release of the next major version.
- Minor versions older than N-1 are not supported.
  > Minor versions are bugfixes or features with non-breaking (additive) API changes.  It is expected apps can upgrade.  Therefore, we will not patch old minor versions of the library. You should also confirm, in issue repros, that you are using the latest minor version before the MSAL.NET team spends time investigating an issue.

## Using Go

- The conceptual documentation is currently available from the [Microsoft identity platform documentation](https://docs.microsoft.com/azure/active-directory/develop/msal-overview) and our [Wiki pages](https://aka.ms/msal-go)

TBD

## Where do I file issues

This is the correct repo to file [issues](https://github.com/AzureAD/microsoft-authentication-library-for-go/issues)

## Requirements

Operating system:
* Any place where Go compiles
 
## Community Help and Support

We use [Stack Overflow](http://stackoverflow.com/questions/tagged/msal) with the community to provide support. We highly recommend you ask your questions on Stack Overflow first and browse existing issues to see if someone has asked your question before.

If you find and bug or have a feature request, please raise the issue on [GitHub Issues](../../issues).

To provide a recommendation, visit our [User Voice page](https://feedback.azure.com/forums/169401-azure-active-directory).

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

Copyright (c) Microsoft Corporation.  All rights reserved. Licensed under the MIT License (the "License");


