//go:build e2e
// +build e2e

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// End-to-end Azure Arc managed identity test.
//
// This test runs only on the self-hosted "MISEAZUREARC" Azure DevOps pool, an
// Azure Arc-enabled machine, and is compiled only under the "e2e" build tag.
// Azure Arc supports the system-assigned identity only, so unlike the IMDS
// tests there are no user-assigned variants.
//
// It mirrors the MSAL .NET Azure Arc E2E test
// (tests/Microsoft.Identity.Test.E2e/ManagedIdentityAzureArcTests.cs) and reuses
// the shared ARM resource and caching assertions from the IMDS test file.

package e2e

import (
	"testing"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

// TestManagedIdentityAzureArc acquires an ARM token for the system-assigned
// identity on an Azure Arc machine, asserting the first call reaches the
// identity provider and the second is served from the token cache.
func TestManagedIdentityAzureArc(t *testing.T) {
	acquireTokenTwiceAssertCaching(t, mi.SystemAssigned())
}
