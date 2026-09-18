// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package attestation provides opt-in KeyGuard attestation for MSAL Go managed
// identity clients.
//
// Importing this module in a Windows amd64 application embeds the authentic
// AttestationClientLib.dll from Microsoft.Azure.Security.KeyGuardAttestation.
// WithSupport extracts, verifies, and loads that library lazily on first use.
// Applications that do not import this module do not link or embed the DLL.
package attestation

import managedidentity "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"

var defaultProvider libraryProvider

// WithSupport enables KeyGuard attestation for a managed identity token
// acquisition. Combine it with managedidentity.WithMtlsProofOfPossession or
// managedidentity.WithRequestOverMtls.
//
// The native library is materialized and loaded only when MSAL needs a new
// attestation statement. Any extraction, verification, loading,
// initialization, or attestation failure fails the acquisition rather than
// silently returning an unattested credential.
func WithSupport() managedidentity.AcquireTokenOption {
	return managedidentity.WithAttestationProvider(&defaultProvider)
}
