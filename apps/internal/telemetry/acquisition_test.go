// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package telemetry

import (
	"context"
	"testing"
	"time"

	publictelemetry "github.com/AzureAD/microsoft-authentication-library-for-go/apps/telemetry"
)

type recordingProvider struct {
	events []publictelemetry.AuthenticationEvent
}

func (p *recordingProvider) RecordAuthentication(_ context.Context, event publictelemetry.AuthenticationEvent) {
	p.events = append(p.events, event)
}

func TestAcquisitionEmitsOnce(t *testing.T) {
	provider := &recordingProvider{}
	ctx, acquisition := Start(
		context.Background(),
		provider,
		publictelemetry.APIIDAcquireTokenForClient,
		publictelemetry.TokenTypeBearer,
		"1.0.0",
	)
	ObserveHTTP(ctx, 10*time.Millisecond, 200)
	acquisition.SetCacheResult(
		publictelemetry.CacheLevelNone,
		publictelemetry.CacheRefreshReasonNoCachedAccessToken,
	)
	expiresOn := time.Now().Add(time.Hour)
	acquisition.Complete(ctx, true, publictelemetry.TokenSourceIdentityProvider, expiresOn, "")
	acquisition.Complete(ctx, false, publictelemetry.TokenSourceCache, time.Time{}, "ignored")

	if len(provider.events) != 1 {
		t.Fatalf("expected one event, got %d", len(provider.events))
	}
	event := provider.events[0]
	if event.APIID != publictelemetry.APIIDAcquireTokenForClient {
		t.Fatalf("APIID = %d", event.APIID)
	}
	if event.HTTPDuration != 10*time.Millisecond || event.HTTPStatusCode != 200 {
		t.Fatalf("unexpected HTTP measurement: %s, %d", event.HTTPDuration, event.HTTPStatusCode)
	}
	if !event.Succeeded || event.TokenSource != publictelemetry.TokenSourceIdentityProvider {
		t.Fatalf("unexpected result: succeeded=%t, source=%d", event.Succeeded, event.TokenSource)
	}
	if !event.ExpiresOn.Equal(expiresOn) {
		t.Fatalf("ExpiresOn = %s, want %s", event.ExpiresOn, expiresOn)
	}
}

func TestNilProviderDoesNotAttachToContext(t *testing.T) {
	ctx := context.Background()
	got, acquisition := Start(
		ctx,
		nil,
		publictelemetry.APIIDAcquireTokenSilent,
		publictelemetry.TokenTypeBearer,
		"1.0.0",
	)
	if got != ctx {
		t.Fatal("disabled telemetry changed the context")
	}
	if acquisition != nil {
		t.Fatal("disabled telemetry created an acquisition")
	}
}

func TestObserveServiceErrorOnlyRecordsBoundedFields(t *testing.T) {
	provider := &recordingProvider{}
	ctx, acquisition := Start(
		context.Background(),
		provider,
		publictelemetry.APIIDAcquireTokenForClient,
		publictelemetry.TokenTypeBearer,
		"1.0.0",
	)
	ObserveServiceError(ctx, []byte(`{
		"error":"invalid_client",
		"error_description":"sensitive-description",
		"error_codes":[7000215],
		"correlation_id":"sensitive-correlation"
	}`))
	acquisition.Complete(ctx, false, publictelemetry.TokenSourceIdentityProvider, time.Time{}, "http_error")

	event := provider.events[0]
	if event.ErrorCode != "invalid_client" {
		t.Fatalf("ErrorCode = %q", event.ErrorCode)
	}
	if event.RawSTSErrorCode != "7000215" {
		t.Fatalf("RawSTSErrorCode = %q", event.RawSTSErrorCode)
	}
}

func TestObserveServiceErrorRejectsUnboundedCode(t *testing.T) {
	provider := &recordingProvider{}
	ctx, acquisition := Start(
		context.Background(),
		provider,
		publictelemetry.APIIDAcquireTokenForClient,
		publictelemetry.TokenTypeBearer,
		"1.0.0",
	)
	ObserveServiceError(ctx, []byte(`{"error":"value with user@example.com"}`))
	acquisition.Complete(ctx, false, publictelemetry.TokenSourceIdentityProvider, time.Time{}, "http_error")

	if got := provider.events[0].ErrorCode; got != "service_error" {
		t.Fatalf("ErrorCode = %q, want service_error", got)
	}
}

func TestTerminalCancellationOverridesPollingError(t *testing.T) {
	provider := &recordingProvider{}
	ctx, acquisition := Start(
		context.Background(),
		provider,
		publictelemetry.APIIDAcquireTokenByDeviceCode,
		publictelemetry.TokenTypeBearer,
		"1.0.0",
	)
	ObserveServiceError(ctx, []byte(`{
		"error":"authorization_pending",
		"error_codes":[70016]
	}`))
	acquisition.Complete(
		ctx,
		false,
		publictelemetry.TokenSourceIdentityProvider,
		time.Time{},
		"context_canceled",
	)

	event := provider.events[0]
	if event.ErrorCode != "context_canceled" {
		t.Fatalf("ErrorCode = %q, want context_canceled", event.ErrorCode)
	}
	if event.RawSTSErrorCode != "" {
		t.Fatalf("RawSTSErrorCode = %q, want empty", event.RawSTSErrorCode)
	}
}
