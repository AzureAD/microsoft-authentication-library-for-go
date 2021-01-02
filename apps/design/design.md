# MSAL Go Design Guide

Author: John Doak(jdoak@microsoft.com)
Contributors: 
- Keegan Caruso(Keegan.Caruso@microsoft.com)
- Joel Hendrix(jhendrix@microsoft.com)
- Santiago Gonzalez(Santiago.Gonzalez@microsoft.com)

## History

The original code submitted for Go MSAL was a translation of either Java or .Net code.  This was done as a best effort by an intern who was attempting their first crack at Go.  It had a
very interesting structure that didn't fit into Go style and made it difficult to understand or
change. It used global locks, global variables, base type classes (mimicing inheritence), ...

This probably should have be re-written from scratch, but we decided to try and do it in pieces.
The lesson to be learned from this is that this type of refactor leads to re-writing the code 7 or 8 times instead of once. 

Much of this lead to a re-write where we were not seeing the forrest because of the trees. Every small change would inevitably become some 60 file refactor and have much larger ramifications than intended.  

The work could not be divided up, because the API and the internals were linked across logical
boundaries.

What has resulted should be a design that divides code into logical layers and splits
the public API from the internal structure. 

## General Structure

Public Surface:
```
apps/ - Contains all our code
  confidential/ - The confidential application API
  public/ - The public application API
  cache/ - The cache interface that can be implemented to provide persistence cache storage of credentials
```

Internals:
```
apps/
  internal/
    client/ - Shared package for common calls that Public and Confidential apps share
    json/ - Our own json encoder/decoder for special needs
    msalbase/ - Holds types that need to be in multiple packages and can't be moved into a single one due to import cycles
    requests/ - The pacakge to communicate to services to get tokens
```

### Use of the Go special internal/ directory

In Go, a directory called internal/ contains packages that should only be used by other packages
rooted at the same location.

This is documented here: https://golang.org/doc/go1.4#internalpackages

For example, a package .../a/b/c/internal/d/e/f can be imported only by code in the directory tree rooted at .../a/b/c. It cannot be imported by code in .../a/b/g or in any other repository.

We use this featurs quite liberally to make clear what is using an internal package.  For example:

```
apps/internal/client - Only can be used by packages defined at apps/
apps/internal/client/internal/storage - Only can be use by package client
```

## Public API

The public API will be encapsulated in apps/.  apps/ has 3 packages of interest to users:

- public/ - This is what MSAL calls the Public Application Client (service client)
- confidential/ - This is what MSAL calls the Confidential Application Client (service)
- cache/ - This provides the interfaces that must be implemented to create peristent caches for any MSAL client

## Internals

In this section we will be talking about internal/.

### JSON Handling

JSON must be handled specially in our app. The basics are, if we receive fields that our
structs do not contain, we cannot drop them.  We must send them back to the service.

To handle that, we use our own custom json package that handles this.

See the design at: [Design](https://github.com/AzureAD/microsoft-authentication-library-for-go/blob/dev/internal/json/design.md)

### Backend communication

Communication to the backends is done via the requests/ package. requests.Token is the client
for all communication.

requests.Token communicates via REST calls that are encapsulated in the ops/ client.

## Adding A Feature

This is the general way to add a new feature to MSAL:

- Add the REST calls to ops.REST
- Add the higher level manipulations to requests.Token
- Add your logic to the app/\<client\> and access the services via your requests.Token

## Notes:

Do we need: AcquireTokenSilent()??  Seems like we could just bake this into other acquire calls automatically????