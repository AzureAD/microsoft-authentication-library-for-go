//go:build e2e
// +build e2e

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// End-to-end Azure Arc managed identity tests.
//
// These tests run only on the self-hosted "MISEAZUREARC" Azure DevOps pool, an
// Azure Arc-enabled machine, and are compiled only under the "e2e" build tag.
// The system-assigned identity is fully supported. User-assigned support depends
// on the Azure Arc agent honoring the request; the user-assigned test below
// requests a non-existent identity, which returns no token on any agent — a
// user-assigned-aware agent surfaces a 404 (identity_not_found), while a legacy
// agent ignores the selector and returns the system-assigned identity, which MSAL
// rejects (fails closed) — so it does not depend on a specific agent version.
//
// They mirror the MSAL .NET Azure Arc E2E tests
// (tests/Microsoft.Identity.Test.E2e/ManagedIdentityAzureArcTests.cs) and reuse
// the shared ARM resource and caching assertions from the IMDS test file.

package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

// TestManagedIdentityAzureArc acquires an ARM token for the system-assigned
// identity on an Azure Arc machine, asserting the first call reaches the
// identity provider and the second is served from the token cache.
func TestManagedIdentityAzureArc(t *testing.T) {
	acquireTokenTwiceAssertCaching(t, mi.SystemAssigned())
}

// TestManagedIdentityAzureArcUserAssignedNotFound requests a user-assigned
// identity that is not assigned to the Azure Arc machine. No token is returned on
// any agent: a user-assigned-aware agent returns 404 (identity_not_found), while a
// legacy agent ignores the selector and returns the system-assigned identity, which
// MSAL rejects (fails closed). Either way MSAL surfaces an error and no token.
// Mirrors the MSAL .NET E2E test AcquireToken_ForNonExistentUami_OnAzureArc_Fails.
func TestManagedIdentityAzureArcUserAssignedNotFound(t *testing.T) {
	client, err := mi.New(mi.UserAssignedClientID("00000000-0000-0000-0000-000000000000"))
	if err != nil {
		t.Fatalf("mi.New failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := client.AcquireToken(ctx, armResource)
	if err == nil {
		t.Fatalf("expected an error for a non-existent user-assigned identity, got token source %v", result.Metadata.TokenSource)
	}
	if result.AccessToken != "" {
		t.Fatal("no token should be returned for a non-existent user-assigned identity")
	}
	// A UAMI-aware agent returns 404 (identity_not_found); a legacy agent ignores the
	// selector and returns the system-assigned identity, which MSAL rejects (fail closed).
	if !strings.Contains(err.Error(), "404") &&
		!strings.Contains(strings.ToLower(err.Error()), "identity_not_found") &&
		!strings.Contains(err.Error(), "did not confirm the requested user-assigned managed identity") {
		t.Fatalf("expected a 404 / identity_not_found or fail-closed error, got: %v", err)
	}
}
