# Release Process

## Pre-release checks

1. Ensure the CI has ran on main
2. Run Azure SDK's tests

```
git clone github.com/Azure/azure-sdk-for-go --single-branch --depth=1
cd azure-sdk-for-go/sdk/azidentity
go mod edit -replace=github.com/AzureAD/microsoft-authentication-library-for-go="TODO: disk path to MSAL repo"
go mod tidy
go test -v ./...
```
