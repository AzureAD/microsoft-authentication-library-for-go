// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package errors provides error types for mTLS PoP operations.
// These error codes are used throughout the mTLS authentication flows.
package errors

// mTLS PoP error codes returned from AAD token endpoints or raised by MSAL validation.
// Mirror the MSAL.NET error code constants for consistency.
const (
	// MtlsPopNoRegion is returned when mTLS PoP is requested without an Azure region.
	// Resolution: call WithAzureRegion("region") or WithAzureRegion(AutoDetectRegion()) on the client.
	MtlsPopNoRegion = "mtls_pop_no_region"

	// MtlsPopNoCert is returned when mTLS PoP is requested without a certificate credential.
	// Resolution: create the client with NewCredFromCert() instead of NewCredFromSecret().
	MtlsPopNoCert = "mtls_pop_no_cert"

	// MtlsPopRequiresTenantedAuthority is returned when the authority URL is not tenanted.
	// Resolution: use a specific tenant ID in the authority URL, not /common or /organizations.
	MtlsPopRequiresTenantedAuthority = "mtls_pop_requires_tenanted_authority"

	// MtlsPopWindowsOnly is returned when IMDSv2 mTLS PoP is requested on a non-Windows platform.
	// The IMDSv2 + CNG KeyGuard path requires Windows.
	MtlsPopWindowsOnly = "mtls_pop_windows_only"

	// MtlsPopImdsNotAvailable is returned when the IMDS endpoint is not reachable.
	// This typically means the application is not running in an Azure VM or the IMDS endpoint
	// is blocked by firewall rules.
	MtlsPopImdsNotAvailable = "mtls_pop_imds_not_available"

	// MtlsPopCredentialIssueFailed is returned when IMDS fails to issue a binding credential.
	MtlsPopCredentialIssueFailed = "mtls_pop_credential_issue_failed"

	// MtlsPopUnsupportedSource is returned when mTLS PoP MI is requested from a non-IMDS source.
	// Only DefaultToIMDS source supports mTLS PoP Managed Identity.
	MtlsPopUnsupportedSource = "mtls_pop_unsupported_source"
)
