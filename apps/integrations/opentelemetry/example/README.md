# MSAL Go OpenTelemetry example

Set credentials for a confidential client that can request a Microsoft Graph
application token:

```powershell
$env:AZURE_TENANT_ID = "..."
$env:AZURE_CLIENT_ID = "..."
$env:AZURE_CLIENT_SECRET = "..."
go run .
```

The program performs an identity-provider acquisition, a cache acquisition, and
an intentionally failed acquisition. It exports the resulting metrics as JSON
to standard output. The output must not contain the configured IDs, secret,
scope, authority, tokens, or error description.
