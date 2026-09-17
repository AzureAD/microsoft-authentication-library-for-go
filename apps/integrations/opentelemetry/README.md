# OpenTelemetry metrics for MSAL Go

This optional module translates MSAL Go's privacy-safe authentication events
into OpenTelemetry metrics. It requires Go 1.25 or later. The core MSAL Go
module remains compatible with Go 1.18 and doesn't depend on OpenTelemetry.

Configure an OpenTelemetry SDK in the application, create an adapter with its
meter provider, and pass the adapter to an MSAL client:

```go
metrics, err := msalotel.New(meterProvider)
if err != nil {
    return err
}
client, err := confidential.New(
    authority,
    clientID,
    credential,
    confidential.WithMetricsProvider(metrics),
)
```

MSAL doesn't configure an SDK or exporter. Applications retain control over
collection, aggregation, sampling, and export.

## Release ordering

This module depends on the `apps/telemetry` contract introduced in the parent
MSAL Go module at `v1.10.0`. Publish the parent module at `v1.10.0` or later
before tagging a release of this adapter module.

The relative `replace` directive in this module supports development and CI in
the MSAL Go repository only. Go doesn't inherit dependency replacement
directives in downstream applications, so it doesn't remove the parent-release
requirement.

## Metrics

| Instrument | Type | Unit |
| --- | --- | --- |
| `MsalSuccess` | Counter | |
| `MsalFailure` | Counter | |
| `MsalTotalDurationV2.1A` | Histogram | `ms` |
| `MsalDurationInL1CacheInUs.1B` | Histogram | `us` |
| `MsalDurationInHttpV2.1A` | Histogram | `ms` |
| `MsalRemainingTokenLifetime.1A` | Histogram | `s` |

The `.1A` and `.1B` suffixes select histogram bucket configurations in
Microsoft's MISE Collector. They are part of the instrument names.

The adapter intentionally doesn't emit the legacy total and HTTP instruments.
MSAL Go also doesn't emit L2-cache or extension-duration metrics because its
current APIs can't measure those outcomes with the same semantics as MSAL.NET.

Use `CanonicalTagsByMetric` to obtain the MSAL-owned attributes for each
instrument.

## Example output

A failed client-credential acquisition emits data equivalent to:

```text
MsalFailure = 1
  MsalVersion: "1.10.0"
  Platform: "linux"
  ErrorCode: "invalid_client"
  ApiId: 1004
  CallerSdkId: ""
  CacheRefreshReason: 2
  TokenType: 1
  RawStsErrorCode: "7000215"

MsalTotalDurationV2.1A = 125 ms
  MsalVersionPlatform: "1.10.0,linux"
  ApiId: 1004
  TokenSource: ""
  CacheLevel: ""
  CacheRefreshReason: 2
  TokenType: 1
  ErrorCode: "invalid_client"
  Succeeded: false

MsalDurationInHttpV2.1A = 118 ms
  MsalVersionPlatform: "1.10.0,linux"
  ApiId: 1004
  TokenType: 1
  HttpStatusCode: 401
```

OpenTelemetry exporters wrap these measurements in their own resource and
scope envelopes. The canonical measurement data contains no client or tenant
ID, account, scope, authority or URL, correlation ID, token, secret, response
body, or error description. The adapter also removes trace and span IDs from
metric exemplars.

## Privacy

Canonical metrics don't include client or tenant IDs, account identifiers,
usernames, scopes, resources, claims, assertions, URLs, correlation IDs,
tokens, secrets, or error descriptions. Service errors are limited to a
bounded OAuth error code and the first numeric STS error code.
