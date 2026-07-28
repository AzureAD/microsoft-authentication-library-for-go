//go:build e2e
// +build e2e

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// End-to-end Managed Identity (IMDS v1) tests.
//
// These tests run only on the self-hosted "MISEManagedIdentity" Azure DevOps
// pool, an Azure VM that has a system-assigned managed identity plus the
// user-assigned managed identities referenced below assigned to it. They are
// compiled and executed only when the "e2e" build tag is supplied, e.g.:
//
//	go test -tags e2e ./apps/tests/e2e/...
//
// The identities and ARM resource below are the SAME ones used by the MSAL .NET
// IMDS E2E tests (tests/Microsoft.Identity.Test.E2e/ManagedIdentityImdsTests.cs),
// so both SDKs exercise the same lab configuration on the same VM.

package e2e

import (
	"context"
	"testing"
	"time"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

const (
	// armResource is the Azure Resource Manager resource used for the IMDS token
	// request. Matches ArmScope in the MSAL .NET IMDS E2E tests.
	armResource = "https://management.azure.com"

	// User-assigned managed identities assigned to the MISEManagedIdentity VM.
	// These values are shared with the MSAL .NET IMDS E2E tests.
	uamiClientID   = "6325cd32-9911-41f3-819c-416cdf9104e7"
	uamiObjectID   = "ecb2ad92-3e30-4505-b79f-ac640d069f24"
	uamiResourceID = "/subscriptions/c1686c51-b717-4fe0-9af3-24a20a41fb0c/resourcegroups/MSIV2-Testing-MSALNET/providers/Microsoft.ManagedIdentity/userAssignedIdentities/msiv2uami"
)

// TestManagedIdentityImds acquires an ARM token over IMDS v1 for the
// system-assigned identity and for each user-assigned identity binding
// (client ID, resource ID, object ID). It asserts the first call reaches the
// identity provider and the second call is served from the token cache.
func TestManagedIdentityImds(t *testing.T) {
	tests := []struct {
		name string
		id   mi.ID
	}{
		{name: "SystemAssigned", id: mi.SystemAssigned()},
		{name: "UserAssigned-ClientID", id: mi.UserAssignedClientID(uamiClientID)},
		{name: "UserAssigned-ResourceID", id: mi.UserAssignedResourceID(uamiResourceID)},
		{name: "UserAssigned-ObjectID", id: mi.UserAssignedObjectID(uamiObjectID)},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			acquireTokenTwiceAssertCaching(t, tc.id)
		})
	}
}

// acquireTokenTwiceAssertCaching acquires an ARM token twice for the given
// managed identity and asserts the first call reaches the identity provider
// while the second is served from the token cache. It is shared by the IMDS and
// Azure Arc E2E tests.
func acquireTokenTwiceAssertCaching(t *testing.T, id mi.ID) {
	t.Helper()

	client, err := mi.New(id)
	if err != nil {
		t.Fatalf("mi.New failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// First call must hit the IMDS endpoint.
	first, err := client.AcquireToken(ctx, armResource)
	if err != nil {
		t.Fatalf("first AcquireToken failed: %v", err)
	}
	if first.AccessToken == "" {
		t.Fatal("AccessToken should not be empty")
	}
	if first.Metadata.TokenSource != mi.TokenSourceIdentityProvider {
		t.Fatalf("first call TokenSource = %v, want IdentityProvider", first.Metadata.TokenSource)
	}

	// Second call must be served from the cache.
	second, err := client.AcquireToken(ctx, armResource)
	if err != nil {
		t.Fatalf("second AcquireToken failed: %v", err)
	}
	if second.Metadata.TokenSource != mi.TokenSourceCache {
		t.Fatalf("second call TokenSource = %v, want Cache", second.Metadata.TokenSource)
	}
	if first.AccessToken != second.AccessToken {
		t.Fatal("cached AccessToken should match the original token")
	}
}
