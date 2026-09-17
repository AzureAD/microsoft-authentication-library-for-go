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
	"go.opentelemetry.io/otel/sdk/metric/exemplar"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/trace"
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

	event := msaltelemetry.AuthenticationEvent{
		APIID:              msaltelemetry.APIIDAcquireTokenForClient,
		CacheLevel:         msaltelemetry.CacheLevelL1,
		CacheRefreshReason: msaltelemetry.CacheRefreshReasonNotApplicable,
		HTTPDuration:       20 * time.Millisecond,
		HTTPStatusCode:     200,
		MSALVersion:        "1.10.0",
		Platform:           "test",
		Succeeded:          true,
		TokenSource:        msaltelemetry.TokenSourceCache,
		TokenType:          msaltelemetry.TokenTypeBearer,
		TotalDuration:      25 * time.Millisecond,
	}
	provider.RecordAuthentication(context.Background(), event)

	var data metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &data); err != nil {
		t.Fatal(err)
	}
	if len(data.ScopeMetrics) != 1 {
		t.Fatalf("scope count = %d, want 1", len(data.ScopeMetrics))
	}
	scope := data.ScopeMetrics[0]
	if scope.Scope.Name != MeterName || scope.Scope.Version != "1.0.0" ||
		scope.Scope.SchemaURL != "" || scope.Scope.Attributes.Len() != 0 {
		t.Fatalf("unexpected instrumentation scope: %#v", scope.Scope)
	}
	metrics := make(map[string]metricdata.Metrics, len(scope.Metrics))
	for _, m := range scope.Metrics {
		metrics[m.Name] = m
	}
	if len(metrics) != 5 {
		t.Fatalf("metric count = %d, want 5: %#v", len(metrics), metrics)
	}

	assertCounterMetric(
		t,
		metrics[successCounterName],
		"",
		"Number of successful token acquisition calls",
		1,
		[]attribute.KeyValue{
			attribute.String("MsalVersion", "1.10.0"),
			attribute.String("Platform", "test"),
			attribute.Int("ApiId", 1004),
			attribute.String("CallerSdkId", ""),
			attribute.Int("TokenSource", 1),
			attribute.Int("CacheRefreshReason", 0),
			attribute.Int("CacheLevel", 2),
			attribute.Int("TokenType", 1),
		},
	)
	assertHistogramMetric(
		t,
		metrics[totalDurationHistogramName],
		"ms",
		"Token acquisition latency including successes and failures",
		25,
		[]attribute.KeyValue{
			attribute.String("MsalVersionPlatform", "1.10.0,test"),
			attribute.Int("ApiId", 1004),
			attribute.String("TokenSource", "1"),
			attribute.String("CacheLevel", "2"),
			attribute.Int("CacheRefreshReason", 0),
			attribute.Int("TokenType", 1),
			attribute.String("ErrorCode", ""),
			attribute.Bool("Succeeded", true),
		},
	)
	assertHistogramMetric(
		t,
		metrics[l1CacheDurationHistogramName],
		"us",
		"Token acquisition latency when the internal cache is used",
		25_000,
		[]attribute.KeyValue{
			attribute.String("MsalVersion", "1.10.0"),
			attribute.String("Platform", "test"),
			attribute.Int("ApiId", 1004),
			attribute.Int("TokenSource", 1),
			attribute.Int("CacheLevel", 2),
			attribute.Int("CacheRefreshReason", 0),
		},
	)
	assertHistogramMetric(
		t,
		metrics[httpDurationHistogramName],
		"ms",
		"Token acquisition HTTP latency including successes and failures",
		20,
		[]attribute.KeyValue{
			attribute.String("MsalVersionPlatform", "1.10.0,test"),
			attribute.Int("ApiId", 1004),
			attribute.Int("TokenType", 1),
			attribute.Int("HttpStatusCode", 200),
		},
	)
	assertHistogramMetric(
		t,
		metrics[remainingLifetimeHistogramName],
		"s",
		"Remaining lifetime of an acquired token",
		0,
		[]attribute.KeyValue{
			attribute.String("MsalVersionPlatform", "1.10.0,test"),
			attribute.Int("ApiId", 1004),
			attribute.Int("TokenSource", 1),
			attribute.Int("CacheLevel", 2),
			attribute.Int("CacheRefreshReason", 0),
			attribute.Int("TokenType", 1),
		},
	)
}

func assertCounterMetric(
	t *testing.T,
	metric metricdata.Metrics,
	unit, description string,
	value int64,
	attributes []attribute.KeyValue,
) {
	t.Helper()
	assertMetricMetadata(t, metric, unit, description)
	sum, ok := metric.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("%s aggregation = %T, want metricdata.Sum[int64]", metric.Name, metric.Data)
	}
	if !sum.IsMonotonic || sum.Temporality != metricdata.CumulativeTemporality ||
		len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != value {
		t.Fatalf("%s unexpected sum: %#v", metric.Name, sum)
	}
	assertAttributeSet(t, metric.Name, sum.DataPoints[0].Attributes, attributes)
}

func assertHistogramMetric(
	t *testing.T,
	metric metricdata.Metrics,
	unit, description string,
	value int64,
	attributes []attribute.KeyValue,
) {
	t.Helper()
	assertMetricMetadata(t, metric, unit, description)
	histogram, ok := metric.Data.(metricdata.Histogram[int64])
	if !ok {
		t.Fatalf("%s aggregation = %T, want metricdata.Histogram[int64]", metric.Name, metric.Data)
	}
	if histogram.Temporality != metricdata.CumulativeTemporality ||
		len(histogram.DataPoints) != 1 ||
		histogram.DataPoints[0].Count != 1 ||
		histogram.DataPoints[0].Sum != value {
		t.Fatalf("%s unexpected histogram: %#v", metric.Name, histogram)
	}
	assertAttributeSet(t, metric.Name, histogram.DataPoints[0].Attributes, attributes)
}

func assertMetricMetadata(t *testing.T, metric metricdata.Metrics, unit, description string) {
	t.Helper()
	if metric.Name == "" {
		t.Fatal("expected metric to be exported")
	}
	if metric.Unit != unit || metric.Description != description {
		t.Fatalf(
			"%s metadata = unit %q, description %q; want unit %q, description %q",
			metric.Name,
			metric.Unit,
			metric.Description,
			unit,
			description,
		)
	}
}

func assertAttributeSet(
	t *testing.T,
	metricName string,
	got attribute.Set,
	attributes []attribute.KeyValue,
) {
	t.Helper()
	want := attribute.NewSet(attributes...)
	if !got.Equals(&want) {
		t.Fatalf("%s attributes = %v, want %v", metricName, got.ToSlice(), want.ToSlice())
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
			assertCounterMetric(
				t,
				m,
				"",
				"Number of failed token acquisition calls",
				1,
				[]attribute.KeyValue{
					attribute.String("MsalVersion", "1.10.0"),
					attribute.String("Platform", "test"),
					attribute.String("ErrorCode", "invalid_client"),
					attribute.Int("ApiId", 1004),
					attribute.String("CallerSdkId", ""),
					attribute.Int("CacheRefreshReason", 0),
					attribute.Int("TokenType", 1),
					attribute.String("RawStsErrorCode", ""),
				},
			)
			return
		}
	}
	t.Fatal("MsalFailure wasn't emitted")
}

func TestProviderExemplarsExcludeTraceAndSpanIDs(t *testing.T) {
	reader := metric.NewManualReader()
	meterProvider := metric.NewMeterProvider(
		metric.WithReader(reader),
		metric.WithExemplarFilter(exemplar.AlwaysOnFilter),
	)
	t.Cleanup(func() {
		if err := meterProvider.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	provider, err := New(meterProvider)
	if err != nil {
		t.Fatal(err)
	}

	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1},
		SpanID:     trace.SpanID{2},
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), spanContext)
	provider.RecordAuthentication(ctx, msaltelemetry.AuthenticationEvent{
		APIID:         msaltelemetry.APIIDAcquireTokenForClient,
		CacheLevel:    msaltelemetry.CacheLevelL1,
		ExpiresOn:     time.Now().Add(time.Hour),
		HTTPDuration:  time.Millisecond,
		MSALVersion:   "1.10.0",
		Platform:      "test",
		Succeeded:     true,
		TokenSource:   msaltelemetry.TokenSourceCache,
		TokenType:     msaltelemetry.TokenTypeBearer,
		TotalDuration: time.Millisecond,
	})
	provider.RecordAuthentication(ctx, msaltelemetry.AuthenticationEvent{
		APIID:         msaltelemetry.APIIDAcquireTokenForClient,
		ErrorCode:     "invalid_client",
		HTTPDuration:  time.Millisecond,
		MSALVersion:   "1.10.0",
		Platform:      "test",
		TokenType:     msaltelemetry.TokenTypeBearer,
		TotalDuration: time.Millisecond,
	})

	var data metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &data); err != nil {
		t.Fatal(err)
	}
	exemplarCount := 0
	checkExemplars := func(exemplars []metricdata.Exemplar[int64]) {
		for _, exemplar := range exemplars {
			exemplarCount++
			if len(exemplar.TraceID) != 0 || len(exemplar.SpanID) != 0 {
				t.Errorf("exemplar exported trace ID %x or span ID %x", exemplar.TraceID, exemplar.SpanID)
			}
		}
	}
	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			switch points := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, point := range points.DataPoints {
					checkExemplars(point.Exemplars)
				}
			case metricdata.Histogram[int64]:
				for _, point := range points.DataPoints {
					checkExemplars(point.Exemplars)
				}
			}
		}
	}
	if exemplarCount == 0 {
		t.Fatal("expected the always-on reservoir to produce exemplars")
	}
}
