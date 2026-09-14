// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package opentelemetry

import (
	"context"
	"sort"
	"testing"
	"time"

	msaltelemetry "github.com/AzureAD/microsoft-authentication-library-for-go/apps/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestProviderEmitsV2Schema(t *testing.T) {
	reader := metric.NewManualReader()
	meterProvider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() {
		if err := meterProvider.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	provider, err := New(meterProvider)
	if err != nil {
		t.Fatal(err)
	}

	provider.RecordAuthentication(context.Background(), msaltelemetry.AuthenticationEvent{
		APIID:              msaltelemetry.APIIDAcquireTokenForClient,
		CacheLevel:         msaltelemetry.CacheLevelNone,
		CacheRefreshReason: msaltelemetry.CacheRefreshReasonNoCachedAccessToken,
		ExpiresOn:          time.Now().Add(time.Hour),
		HTTPDuration:       20 * time.Millisecond,
		HTTPStatusCode:     200,
		MSALVersion:        "1.10.0",
		Platform:           "test",
		Succeeded:          true,
		TokenSource:        msaltelemetry.TokenSourceIdentityProvider,
		TokenType:          msaltelemetry.TokenTypeBearer,
		TotalDuration:      25 * time.Millisecond,
	})

	var data metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &data); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			names = append(names, m.Name)
		}
	}
	sort.Strings(names)
	want := []string{
		httpDurationHistogramName,
		remainingLifetimeHistogramName,
		successCounterName,
		totalDurationHistogramName,
	}
	sort.Strings(want)
	if len(names) != len(want) {
		t.Fatalf("metric names = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("metric names = %v, want %v", names, want)
		}
	}
}

func TestCanonicalTagsMatchRecordedAttributes(t *testing.T) {
	event := msaltelemetry.AuthenticationEvent{
		APIID:              msaltelemetry.APIIDAcquireTokenForClient,
		CacheLevel:         msaltelemetry.CacheLevelL1,
		CacheRefreshReason: msaltelemetry.CacheRefreshReasonNotApplicable,
		ErrorCode:          "invalid_client",
		MSALVersion:        "1.10.0",
		Platform:           "test",
		RawSTSErrorCode:    "7000215",
		Succeeded:          true,
		TokenSource:        msaltelemetry.TokenSourceCache,
		TokenType:          msaltelemetry.TokenTypeBearer,
	}
	tests := map[string][]attribute.KeyValue{
		successCounterName:             successAttributes(event),
		failureCounterName:             failureAttributes(event),
		totalDurationHistogramName:     totalDurationAttributes(event),
		l1CacheDurationHistogramName:   l1CacheAttributes(event),
		httpDurationHistogramName:      httpDurationAttributes(event),
		remainingLifetimeHistogramName: remainingLifetimeAttributes(event),
	}
	catalog := CanonicalTagsByMetric()
	for metricName, attributes := range tests {
		var got []string
		for _, attr := range attributes {
			got = append(got, string(attr.Key))
		}
		want := catalog[metricName]
		sort.Strings(got)
		sort.Strings(want)
		if len(got) != len(want) {
			t.Fatalf("%s tags = %v, want %v", metricName, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s tags = %v, want %v", metricName, got, want)
			}
		}
	}
}

func TestProviderFailureHasStableRawSTSErrorTag(t *testing.T) {
	reader := metric.NewManualReader()
	meterProvider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() {
		if err := meterProvider.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	provider, err := New(meterProvider)
	if err != nil {
		t.Fatal(err)
	}

	provider.RecordAuthentication(context.Background(), msaltelemetry.AuthenticationEvent{
		APIID:         msaltelemetry.APIIDAcquireTokenForClient,
		ErrorCode:     "invalid_client",
		MSALVersion:   "1.10.0",
		Platform:      "test",
		TokenType:     msaltelemetry.TokenTypeBearer,
		TotalDuration: time.Millisecond,
	})

	var data metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &data); err != nil {
		t.Fatal(err)
	}
	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != failureCounterName {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok || len(sum.DataPoints) != 1 {
				t.Fatalf("unexpected failure metric data: %#v", m.Data)
			}
			value, ok := sum.DataPoints[0].Attributes.Value("RawStsErrorCode")
			if !ok || value.AsString() != "" {
				t.Fatalf("RawStsErrorCode = %q, present=%t", value.AsString(), ok)
			}
			return
		}
	}
	t.Fatal("MsalFailure wasn't emitted")
}
