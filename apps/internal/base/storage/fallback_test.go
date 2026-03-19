// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package storage

import (
	"context"
	"errors"
	"testing"

	msalerrors "github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

// fakeDiscoveryClient lets tests control AADInstanceDiscovery behavior,
// including returning specific error types and tracking call count.
type fakeDiscoveryClient struct {
	err       error
	ret       authority.InstanceDiscoveryResponse
	callCount int
}

func (f *fakeDiscoveryClient) AADInstanceDiscovery(ctx context.Context, authorityInfo authority.Info) (authority.InstanceDiscoveryResponse, error) {
	f.callCount++
	if f.err != nil {
		return authority.InstanceDiscoveryResponse{}, f.err
	}
	return f.ret, nil
}

// TestAadMetadataFallbackOnNetworkError verifies that when instance discovery
// fails with a transient network error for a known cloud host, the storage
// layer returns known metadata (with all aliases) instead of propagating the
// error. This ensures token acquisition can proceed during ESTS outages.
func TestAadMetadataFallbackOnNetworkError(t *testing.T) {
	// Arrange
	fake := &fakeDiscoveryClient{err: errors.New("network timeout")}
	m := newForTest(fake)
	info := authority.Info{Host: "login.microsoftonline.com", Tenant: "tenant"}

	// Act
	md, err := m.aadMetadata(context.Background(), info)

	// Assert: no error, and we get the full public cloud alias set from known metadata
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(md.Aliases) != 4 {
		t.Errorf("expected 4 aliases for public cloud fallback, got %d: %v", len(md.Aliases), md.Aliases)
	}
	if md.PreferredNetwork != "login.microsoftonline.com" {
		t.Errorf("PreferredNetwork = %q, want %q", md.PreferredNetwork, "login.microsoftonline.com")
	}
	if md.PreferredCache != "login.windows.net" {
		t.Errorf("PreferredCache = %q, want %q (should use known cache host)", md.PreferredCache, "login.windows.net")
	}
}

// TestAadMetadataFallbackUnknownHost verifies that when instance discovery
// fails for a host that is NOT in the known metadata provider, the fallback
// creates a self-entry with only the requested host as an alias. This ensures
// token acquisition can still proceed but without cross-alias SSO benefits.
func TestAadMetadataFallbackUnknownHost(t *testing.T) {
	// Arrange
	fake := &fakeDiscoveryClient{err: errors.New("HTTP 500")}
	m := newForTest(fake)
	info := authority.Info{Host: "custom.unknown.example.com", Tenant: "tenant"}

	// Act
	md, err := m.aadMetadata(context.Background(), info)

	// Assert: no error, self-entry with only the requested host
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(md.Aliases) != 1 {
		t.Errorf("expected 1 alias for unknown host fallback, got %d: %v", len(md.Aliases), md.Aliases)
	}
	if md.Aliases[0] != "custom.unknown.example.com" {
		t.Errorf("expected alias to be the host itself, got %q", md.Aliases[0])
	}
	if md.PreferredNetwork != "custom.unknown.example.com" {
		t.Errorf("PreferredNetwork = %q, want %q", md.PreferredNetwork, "custom.unknown.example.com")
	}
	if md.PreferredCache != "custom.unknown.example.com" {
		t.Errorf("PreferredCache = %q, want %q", md.PreferredCache, "custom.unknown.example.com")
	}
}

// TestAadMetadataInvalidInstancePropagates verifies that an invalid_instance
// error from the discovery endpoint is NOT swallowed by fallback logic and
// propagates to the caller. This matches MSAL .NET behavior: a genuinely
// invalid authority should fail fast, not silently succeed with a fallback.
func TestAadMetadataInvalidInstancePropagates(t *testing.T) {
	// Arrange
	fake := &fakeDiscoveryClient{
		err: msalerrors.InvalidInstanceDiscoveryError{Err: errors.New("invalid instance")},
	}
	m := newForTest(fake)
	info := authority.Info{Host: "bad.example.com", Tenant: "tenant"}

	// Act
	_, err := m.aadMetadata(context.Background(), info)

	// Assert: error propagated, and it's specifically an InvalidInstanceDiscoveryError
	if err == nil {
		t.Fatal("expected error for invalid_instance, got nil")
	}
	var invalidErr msalerrors.InvalidInstanceDiscoveryError
	if !errors.As(err, &invalidErr) {
		t.Errorf("expected InvalidInstanceDiscoveryError, got %T: %v", err, err)
	}
}

// TestAadMetadataContextCancellationPropagates verifies that when the caller
// cancels the context, the cancellation error is propagated rather than being
// swallowed by fallback logic. Without this check, a canceled request could
// silently succeed with stale/fallback data instead of respecting the caller's
// intent to abort.
func TestAadMetadataContextCancellationPropagates(t *testing.T) {
	// Arrange: cancel the context before the call
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fake := &fakeDiscoveryClient{err: ctx.Err()}
	m := newForTest(fake)
	info := authority.Info{Host: "login.microsoftonline.com", Tenant: "tenant"}

	// Act
	_, err := m.aadMetadata(ctx, info)

	// Assert: cancellation error is NOT swallowed
	if err == nil {
		t.Fatal("expected error for canceled context, got nil")
	}
}

// TestAadMetadataFallbackIsCached verifies that after a transient discovery
// failure, the fallback metadata is written to cache so that subsequent calls
// return immediately from cache without retrying the failing network call.
// This prevents repeated network requests during an outage.
func TestAadMetadataFallbackIsCached(t *testing.T) {
	// Arrange
	fake := &fakeDiscoveryClient{err: errors.New("server error")}
	m := &Manager{requests: fake, aadCache: make(map[string]authority.InstanceDiscoveryMetadata)}
	m.contract = NewContract()
	info := authority.Info{Host: "login.microsoftonline.com", Tenant: "tenant"}

	// Act: first call triggers discovery (fails) and populates fallback cache
	md1, err := m.aadMetadata(context.Background(), info)
	if err != nil {
		t.Fatalf("first call: expected no error, got %v", err)
	}
	if fake.callCount != 1 {
		t.Fatalf("expected 1 discovery call, got %d", fake.callCount)
	}

	// Assert: the fallback entry is in cache and second call uses it (no new discovery call)
	cached, cacheErr := m.aadMetadataFromCache(context.Background(), info)
	if cacheErr != nil {
		t.Fatal("expected fallback to be in cache after first call")
	}
	if cached.PreferredNetwork != md1.PreferredNetwork {
		t.Errorf("cached PreferredNetwork = %q, want %q", cached.PreferredNetwork, md1.PreferredNetwork)
	}

	// getMetadataEntry checks cache first, so the second call should not trigger discovery
	_, err = m.getMetadataEntry(context.Background(), info)
	if err != nil {
		t.Fatalf("second call: expected no error, got %v", err)
	}
	if fake.callCount != 1 {
		t.Errorf("expected discovery to be called only once (cached), but got %d calls", fake.callCount)
	}
}

// TestAadMetadataFallbackSovereignCloud verifies that fallback works correctly
// for sovereign cloud hosts (Bleu/Delos/GovSG). The known metadata provider
// should return the correct single-alias entry for sovereignty-isolated clouds.
func TestAadMetadataFallbackSovereignCloud(t *testing.T) {
	// Arrange
	fake := &fakeDiscoveryClient{err: errors.New("server error")}
	m := newForTest(fake)
	info := authority.Info{Host: "login.sovcloud-identity.fr", Tenant: "tenant"}

	// Act
	md, err := m.aadMetadata(context.Background(), info)

	// Assert: Bleu cloud is known, so the fallback should use its known metadata
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if md.PreferredNetwork != "login.sovcloud-identity.fr" {
		t.Errorf("PreferredNetwork = %q, want %q", md.PreferredNetwork, "login.sovcloud-identity.fr")
	}
	// Sovereign clouds are isolated — they should have exactly 1 alias (themselves)
	if len(md.Aliases) != 1 {
		t.Errorf("expected 1 alias for Bleu cloud, got %d: %v", len(md.Aliases), md.Aliases)
	}
	if md.Aliases[0] != "login.sovcloud-identity.fr" {
		t.Errorf("expected alias to be %q, got %q", "login.sovcloud-identity.fr", md.Aliases[0])
	}
}

// --- PartitionedManager tests ---
//
// PartitionedManager is used for on-behalf-of (OBO) flows and has its own
// aadMetadata/fallbackMetadata implementation with separate locking. These
// tests verify the same fallback behavior applies to the OBO cache path.

// TestPartitionedAadMetadataFallbackOnNetworkError verifies the PartitionedManager
// fallback path returns known metadata on transient failure, matching Manager behavior.
func TestPartitionedAadMetadataFallbackOnNetworkError(t *testing.T) {
	// Arrange
	fake := &fakeDiscoveryClient{err: errors.New("network timeout")}
	pm := &PartitionedManager{requests: fake, aadCache: make(map[string]authority.InstanceDiscoveryMetadata)}
	pm.contract = NewInMemoryContract()
	info := authority.Info{Host: "login.microsoftonline.com", Tenant: "tenant"}

	// Act
	md, err := pm.aadMetadata(context.Background(), info)

	// Assert: same known metadata fallback as Manager
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(md.Aliases) != 4 {
		t.Errorf("expected 4 aliases for public cloud fallback, got %d: %v", len(md.Aliases), md.Aliases)
	}
}

// TestPartitionedAadMetadataInvalidInstancePropagates verifies that the
// PartitionedManager also propagates invalid_instance errors, matching Manager.
func TestPartitionedAadMetadataInvalidInstancePropagates(t *testing.T) {
	// Arrange
	fake := &fakeDiscoveryClient{
		err: msalerrors.InvalidInstanceDiscoveryError{Err: errors.New("invalid instance")},
	}
	pm := &PartitionedManager{requests: fake, aadCache: make(map[string]authority.InstanceDiscoveryMetadata)}
	pm.contract = NewInMemoryContract()
	info := authority.Info{Host: "bad.example.com", Tenant: "tenant"}

	// Act
	_, err := pm.aadMetadata(context.Background(), info)

	// Assert
	if err == nil {
		t.Fatal("expected error for invalid_instance, got nil")
	}
	var invalidErr msalerrors.InvalidInstanceDiscoveryError
	if !errors.As(err, &invalidErr) {
		t.Errorf("expected InvalidInstanceDiscoveryError, got %T: %v", err, err)
	}
}

// TestPartitionedAadMetadataContextCancellationPropagates verifies the
// PartitionedManager also propagates context cancellation, matching Manager.
func TestPartitionedAadMetadataContextCancellationPropagates(t *testing.T) {
	// Arrange
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fake := &fakeDiscoveryClient{err: ctx.Err()}
	pm := &PartitionedManager{requests: fake, aadCache: make(map[string]authority.InstanceDiscoveryMetadata)}
	pm.contract = NewInMemoryContract()
	info := authority.Info{Host: "login.microsoftonline.com", Tenant: "tenant"}

	// Act
	_, err := pm.aadMetadata(ctx, info)

	// Assert
	if err == nil {
		t.Fatal("expected error for canceled context, got nil")
	}
}
