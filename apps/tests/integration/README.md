# Go Integration Test

This guide explains how to:

1. Download a certificate from [link](https://ms.portal.azure.com/#@microsoft.onmicrosoft.com/asset/Microsoft_Azure_KeyVault/Certificate/https://msidlabs.vault.azure.net/certificates/LabAuth).
2. Download the `.pex/.pem` format
3. Convert the `.cert` file to `.pem` file.
4. Execute Go integration tests.

## Prerequisites

- Run `openssl pkcs12 -in <path to the cert>/cert.pfx -out <Go source folder>/cert.pem -nodes -passin pass:''`
- It should be in the root folder of the `microsoft-authentication-library-for-go`

## Steps

### 1. Running the tests

```bash
go test -race ./apps/tests/integration/
```
