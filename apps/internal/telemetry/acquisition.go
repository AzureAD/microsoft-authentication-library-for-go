// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	msalerrors "github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	publictelemetry "github.com/AzureAD/microsoft-authentication-library-for-go/apps/telemetry"
)

type acquisitionKey struct{}

// Acquisition accumulates measurements for one caller-facing token acquisition.
type Acquisition struct {
	mu        sync.Mutex
	provider  publictelemetry.MetricsProvider
	event     publictelemetry.AuthenticationEvent
	started   time.Time
	completed bool
}

// Start adds a new acquisition to ctx. A nil provider keeps the path disabled.
func Start(
	ctx context.Context,
	provider publictelemetry.MetricsProvider,
	apiID publictelemetry.APIID,
	tokenType publictelemetry.TokenType,
	msalVersion string,
) (context.Context, *Acquisition) {
	if provider == nil {
		return ctx, nil
	}
	a := &Acquisition{
		provider: provider,
		started:  time.Now(),
		event: publictelemetry.AuthenticationEvent{
			APIID:       apiID,
			MSALVersion: msalVersion,
			Platform:    runtime.GOOS,
			TokenType:   tokenType,
		},
	}
	return context.WithValue(ctx, acquisitionKey{}, a), a
}

// ObserveHTTP adds one HTTP exchange to the acquisition in ctx.
func ObserveHTTP(ctx context.Context, duration time.Duration, statusCode int) {
	a, _ := ctx.Value(acquisitionKey{}).(*Acquisition)
	if a == nil {
		return
	}
	a.mu.Lock()
	a.event.HTTPDuration += duration
	a.event.HTTPStatusCode = statusCode
	a.mu.Unlock()
}

// ObserveServiceError records the structured OAuth error fields from a failed
// response. Arbitrary descriptions and additional fields are ignored.
func ObserveServiceError(ctx context.Context, data []byte) {
	a, _ := ctx.Value(acquisitionKey{}).(*Acquisition)
	if a == nil {
		return
	}
	response := struct {
		Error      string `json:"error"`
		ErrorCodes []int  `json:"error_codes"`
	}{}
	if json.Unmarshal(data, &response) != nil {
		a.SetServiceError("", "")
		return
	}
	errorCode := boundedErrorCode(response.Error)
	rawSTSErrorCode := ""
	if len(response.ErrorCodes) > 0 {
		rawSTSErrorCode = strconv.Itoa(response.ErrorCodes[0])
	}
	a.SetServiceError(errorCode, rawSTSErrorCode)
}

// ObserveErrorCode records an MSAL-owned bounded error category.
func ObserveErrorCode(ctx context.Context, errorCode string) {
	a, _ := ctx.Value(acquisitionKey{}).(*Acquisition)
	if a == nil {
		return
	}
	a.SetServiceError(errorCode, "")
}

// ObserveErrorCodeIfUnset records an MSAL-owned error category unless a lower
// layer has already recorded a more specific classification.
func ObserveErrorCodeIfUnset(ctx context.Context, errorCode string) {
	a, _ := ctx.Value(acquisitionKey{}).(*Acquisition)
	if a == nil {
		return
	}
	a.mu.Lock()
	if a.event.ErrorCode == "" {
		a.event.ErrorCode = errorCode
		a.event.RawSTSErrorCode = ""
	}
	a.mu.Unlock()
}

func boundedErrorCode(value string) string {
	if value == "" {
		return ""
	}
	switch strings.ToLower(value) {
	case "access_denied",
		"authorization_pending",
		"consent_required",
		"expired_token",
		"interaction_required",
		"invalid_client",
		"invalid_grant",
		"invalid_request",
		"invalid_resource",
		"invalid_scope",
		"invalid_target",
		"login_required",
		"server_error",
		"slow_down",
		"temporarily_unavailable",
		"unauthorized_client",
		"unsupported_grant_type":
		return strings.ToLower(value)
	default:
		return "service_error"
	}
}

// Continue attaches an existing acquisition to another context.
func Continue(ctx context.Context, acquisition *Acquisition) context.Context {
	if acquisition == nil {
		return ctx
	}
	return context.WithValue(ctx, acquisitionKey{}, acquisition)
}

// ErrorCode returns a bounded classification without exposing error text.
func ErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled):
		return "context_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "context_deadline_exceeded"
	}
	var callErr msalerrors.CallErr
	if errors.As(err, &callErr) {
		return "http_error"
	}
	var invalidJSON msalerrors.InvalidJsonErr
	if errors.As(err, &invalidJSON) {
		return "invalid_response"
	}
	return "internal_error"
}

// SetCacheResult records the final cache outcome.
func (a *Acquisition) SetCacheResult(
	level publictelemetry.CacheLevel,
	reason publictelemetry.CacheRefreshReason,
) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.event.CacheLevel = level
	a.event.CacheRefreshReason = reason
	a.mu.Unlock()
}

// ObserveCacheResult records the final cache outcome for the acquisition in ctx.
func ObserveCacheResult(
	ctx context.Context,
	level publictelemetry.CacheLevel,
	reason publictelemetry.CacheRefreshReason,
) {
	a, _ := ctx.Value(acquisitionKey{}).(*Acquisition)
	a.SetCacheResult(level, reason)
}

// ObserveTokenType maps an authentication scheme to MSAL's bounded taxonomy.
func ObserveTokenType(ctx context.Context, accessTokenType string) {
	a, _ := ctx.Value(acquisitionKey{}).(*Acquisition)
	if a == nil {
		return
	}
	var tokenType publictelemetry.TokenType
	if strings.EqualFold(accessTokenType, "Bearer") {
		tokenType = publictelemetry.TokenTypeBearer
	} else {
		// AuthenticationScheme is currently exposed only for Azure Arc PoP.
		tokenType = publictelemetry.TokenTypePoP
	}
	a.mu.Lock()
	a.event.TokenType = tokenType
	a.mu.Unlock()
}

// SetServiceError records structured, logging-safe service error values.
func (a *Acquisition) SetServiceError(errorCode, rawSTSErrorCode string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.event.ErrorCode = errorCode
	a.event.RawSTSErrorCode = rawSTSErrorCode
	a.mu.Unlock()
}

// Complete emits the final event at most once.
func (a *Acquisition) Complete(
	ctx context.Context,
	succeeded bool,
	tokenSource publictelemetry.TokenSource,
	expiresOn time.Time,
	errorCode string,
) {
	if a == nil {
		return
	}
	a.mu.Lock()
	if a.completed {
		a.mu.Unlock()
		return
	}
	a.completed = true
	a.event.Succeeded = succeeded
	a.event.TokenSource = tokenSource
	a.event.ExpiresOn = expiresOn
	a.event.TotalDuration = time.Since(a.started)
	if succeeded {
		a.event.ErrorCode = ""
		a.event.RawSTSErrorCode = ""
	} else if errorCode == "context_canceled" || errorCode == "context_deadline_exceeded" {
		a.event.ErrorCode = errorCode
		a.event.RawSTSErrorCode = ""
	} else if a.event.ErrorCode == "" {
		a.event.ErrorCode = errorCode
	}
	event := a.event
	provider := a.provider
	a.mu.Unlock()

	if provider != nil {
		provider.RecordAuthentication(ctx, event)
	}
}
