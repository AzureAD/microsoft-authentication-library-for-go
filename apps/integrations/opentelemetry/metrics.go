// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package opentelemetry adapts MSAL's privacy-safe authentication events to
// OpenTelemetry metrics. It requires Go 1.25 or later; the core MSAL module
// remains compatible with Go 1.18.
package opentelemetry

import (
	"context"
	"fmt"
	"time"

	msaltelemetry "github.com/AzureAD/microsoft-authentication-library-for-go/apps/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// MeterName is the OpenTelemetry instrumentation scope used by MSAL metrics.
const MeterName = "MicrosoftIdentityClient_Common_Meter"

const (
	successCounterName             = "MsalSuccess"
	failureCounterName             = "MsalFailure"
	totalDurationHistogramName     = "MsalTotalDurationV2.1A"
	l1CacheDurationHistogramName   = "MsalDurationInL1CacheInUs.1B"
	httpDurationHistogramName      = "MsalDurationInHttpV2.1A"
	remainingLifetimeHistogramName = "MsalRemainingTokenLifetime.1A"
)

var canonicalTags = map[string][]string{
	successCounterName: {
		"MsalVersion",
		"Platform",
		"ApiId",
		"CallerSdkId",
		"TokenSource",
		"CacheRefreshReason",
		"CacheLevel",
		"TokenType",
	},
	failureCounterName: {
		"MsalVersion",
		"Platform",
		"ErrorCode",
		"ApiId",
		"CallerSdkId",
		"CacheRefreshReason",
		"TokenType",
		"RawStsErrorCode",
	},
	totalDurationHistogramName: {
		"MsalVersionPlatform",
		"ApiId",
		"TokenSource",
		"CacheLevel",
		"CacheRefreshReason",
		"TokenType",
		"ErrorCode",
		"Succeeded",
	},
	l1CacheDurationHistogramName: {
		"MsalVersion",
		"Platform",
		"ApiId",
		"TokenSource",
		"CacheLevel",
		"CacheRefreshReason",
	},
	httpDurationHistogramName: {
		"MsalVersionPlatform",
		"ApiId",
		"TokenType",
		"HttpStatusCode",
	},
	remainingLifetimeHistogramName: {
		"MsalVersionPlatform",
		"ApiId",
		"TokenSource",
		"CacheLevel",
		"CacheRefreshReason",
		"TokenType",
	},
}

// CanonicalTagsByMetric returns the MSAL-owned attributes for each metric.
// The returned map and slices are copies and can be safely modified.
func CanonicalTagsByMetric() map[string][]string {
	tags := make(map[string][]string, len(canonicalTags))
	for metricName, keys := range canonicalTags {
		tags[metricName] = append([]string(nil), keys...)
	}
	return tags
}

// Recorder translates MSAL authentication events into OpenTelemetry metrics.
type Recorder struct {
	successCounter             metric.Int64Counter
	failureCounter             metric.Int64Counter
	totalDurationHistogram     metric.Int64Histogram
	l1CacheDurationHistogram   metric.Int64Histogram
	httpDurationHistogram      metric.Int64Histogram
	remainingLifetimeHistogram metric.Int64Histogram
}

// New creates an MSAL metrics recorder using meterProvider.
func New(meterProvider metric.MeterProvider) (*Recorder, error) {
	if meterProvider == nil {
		return nil, fmt.Errorf("meter provider cannot be nil")
	}
	meter := meterProvider.Meter(MeterName, metric.WithInstrumentationVersion("1.0.0"))

	successCounter, err := meter.Int64Counter(
		successCounterName,
		metric.WithDescription("Number of successful token acquisition calls"),
	)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", successCounterName, err)
	}
	failureCounter, err := meter.Int64Counter(
		failureCounterName,
		metric.WithDescription("Number of failed token acquisition calls"),
	)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", failureCounterName, err)
	}
	totalDuration, err := meter.Int64Histogram(
		totalDurationHistogramName,
		metric.WithUnit("ms"),
		metric.WithDescription("Token acquisition latency including successes and failures"),
	)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", totalDurationHistogramName, err)
	}
	l1CacheDuration, err := meter.Int64Histogram(
		l1CacheDurationHistogramName,
		metric.WithUnit("us"),
		metric.WithDescription("Token acquisition latency when the internal cache is used"),
	)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", l1CacheDurationHistogramName, err)
	}
	httpDuration, err := meter.Int64Histogram(
		httpDurationHistogramName,
		metric.WithUnit("ms"),
		metric.WithDescription("Token acquisition HTTP latency including successes and failures"),
	)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", httpDurationHistogramName, err)
	}
	remainingLifetime, err := meter.Int64Histogram(
		remainingLifetimeHistogramName,
		metric.WithUnit("s"),
		metric.WithDescription("Remaining lifetime of an acquired token"),
	)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", remainingLifetimeHistogramName, err)
	}

	return &Recorder{
		successCounter:             successCounter,
		failureCounter:             failureCounter,
		totalDurationHistogram:     totalDuration,
		l1CacheDurationHistogram:   l1CacheDuration,
		httpDurationHistogram:      httpDuration,
		remainingLifetimeHistogram: remainingLifetime,
	}, nil
}

// RecordAuthentication implements telemetry.MetricsRecorder.
func (r *Recorder) RecordAuthentication(ctx context.Context, event msaltelemetry.AuthenticationEvent) {
	metricCtx := trace.ContextWithSpanContext(ctx, trace.SpanContext{})
	if event.Succeeded {
		r.successCounter.Add(metricCtx, 1, metric.WithAttributes(successAttributes(event)...))
	} else {
		r.failureCounter.Add(metricCtx, 1, metric.WithAttributes(failureAttributes(event)...))
	}

	r.totalDurationHistogram.Record(
		metricCtx,
		event.TotalDuration.Milliseconds(),
		metric.WithAttributes(totalDurationAttributes(event)...),
	)

	if event.HTTPDuration > 0 {
		r.httpDurationHistogram.Record(
			metricCtx,
			event.HTTPDuration.Milliseconds(),
			metric.WithAttributes(httpDurationAttributes(event)...),
		)
	}

	if event.Succeeded && event.TokenSource == msaltelemetry.TokenSourceCache &&
		event.CacheLevel == msaltelemetry.CacheLevelL1 {
		r.l1CacheDurationHistogram.Record(
			metricCtx,
			event.TotalDuration.Microseconds(),
			metric.WithAttributes(l1CacheAttributes(event)...),
		)
	}

	if event.Succeeded {
		remaining := max(time.Until(event.ExpiresOn).Seconds(), 0)
		r.remainingLifetimeHistogram.Record(
			metricCtx,
			int64(remaining),
			metric.WithAttributes(remainingLifetimeAttributes(event)...),
		)
	}
}

func successAttributes(event msaltelemetry.AuthenticationEvent) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("MsalVersion", event.MSALVersion),
		attribute.String("Platform", event.Platform),
		attribute.Int("ApiId", int(event.APIID)),
		attribute.String("CallerSdkId", ""),
		attribute.Int("TokenSource", int(event.TokenSource)),
		attribute.Int("CacheRefreshReason", int(event.CacheRefreshReason)),
		attribute.Int("CacheLevel", int(event.CacheLevel)),
		attribute.Int("TokenType", int(event.TokenType)),
	}
}

func failureAttributes(event msaltelemetry.AuthenticationEvent) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("MsalVersion", event.MSALVersion),
		attribute.String("Platform", event.Platform),
		attribute.String("ErrorCode", event.ErrorCode),
		attribute.Int("ApiId", int(event.APIID)),
		attribute.String("CallerSdkId", ""),
		attribute.Int("CacheRefreshReason", int(event.CacheRefreshReason)),
		attribute.Int("TokenType", int(event.TokenType)),
		attribute.String("RawStsErrorCode", event.RawSTSErrorCode),
	}
}

func totalDurationAttributes(event msaltelemetry.AuthenticationEvent) []attribute.KeyValue {
	tokenSource := ""
	cacheLevel := ""
	if event.Succeeded {
		tokenSource = fmt.Sprint(int(event.TokenSource))
		cacheLevel = fmt.Sprint(int(event.CacheLevel))
	}
	errorCode := event.ErrorCode
	if event.Succeeded {
		errorCode = ""
	}
	return []attribute.KeyValue{
		attribute.String("MsalVersionPlatform", event.MSALVersion+","+event.Platform),
		attribute.Int("ApiId", int(event.APIID)),
		attribute.String("TokenSource", tokenSource),
		attribute.String("CacheLevel", cacheLevel),
		attribute.Int("CacheRefreshReason", int(event.CacheRefreshReason)),
		attribute.Int("TokenType", int(event.TokenType)),
		attribute.String("ErrorCode", errorCode),
		attribute.Bool("Succeeded", event.Succeeded),
	}
}

func httpDurationAttributes(event msaltelemetry.AuthenticationEvent) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("MsalVersionPlatform", event.MSALVersion+","+event.Platform),
		attribute.Int("ApiId", int(event.APIID)),
		attribute.Int("TokenType", int(event.TokenType)),
		attribute.Int("HttpStatusCode", event.HTTPStatusCode),
	}
}

func l1CacheAttributes(event msaltelemetry.AuthenticationEvent) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("MsalVersion", event.MSALVersion),
		attribute.String("Platform", event.Platform),
		attribute.Int("ApiId", int(event.APIID)),
		attribute.Int("TokenSource", int(event.TokenSource)),
		attribute.Int("CacheLevel", int(event.CacheLevel)),
		attribute.Int("CacheRefreshReason", int(event.CacheRefreshReason)),
	}
}

func remainingLifetimeAttributes(event msaltelemetry.AuthenticationEvent) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("MsalVersionPlatform", event.MSALVersion+","+event.Platform),
		attribute.Int("ApiId", int(event.APIID)),
		attribute.Int("TokenSource", int(event.TokenSource)),
		attribute.Int("CacheLevel", int(event.CacheLevel)),
		attribute.Int("CacheRefreshReason", int(event.CacheRefreshReason)),
		attribute.Int("TokenType", int(event.TokenType)),
	}
}
