// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package telemetry defines the privacy-safe metrics contract emitted by MSAL.
//
// MSAL doesn't configure an observability backend. Applications can provide a
// MetricsProvider through client options, for example by using the optional
// OpenTelemetry integration.
package telemetry

import (
	"context"
	"time"
)

// MetricsProvider receives one event for each completed token acquisition.
// Implementations must be safe for concurrent use and return promptly.
type MetricsProvider interface {
	RecordAuthentication(context.Context, AuthenticationEvent)
}

// AuthenticationEvent contains bounded, privacy-safe measurements for one
// completed token acquisition. It intentionally excludes request identifiers,
// client and tenant identifiers, scopes, claims, URLs, tokens, and error text.
type AuthenticationEvent struct {
	APIID              APIID
	CacheLevel         CacheLevel
	CacheRefreshReason CacheRefreshReason
	ErrorCode          string
	ExpiresOn          time.Time
	HTTPDuration       time.Duration
	HTTPStatusCode     int
	MSALVersion        string
	Platform           string
	RawSTSErrorCode    string
	Succeeded          bool
	TokenSource        TokenSource
	TokenType          TokenType
	TotalDuration      time.Duration
}

// APIID identifies the caller-facing MSAL operation. Values match MSAL.NET.
type APIID int

const (
	APIIDAcquireTokenByAuthorizationCode           APIID = 1000
	APIIDAcquireTokenByRefreshToken                APIID = 1001
	APIIDAcquireTokenByUsernamePassword            APIID = 1003
	APIIDAcquireTokenForClient                     APIID = 1004
	APIIDAcquireTokenInteractive                   APIID = 1005
	APIIDAcquireTokenOnBehalfOf                    APIID = 1006
	APIIDAcquireTokenSilent                        APIID = 1007
	APIIDAcquireTokenByDeviceCode                  APIID = 1008
	APIIDAcquireTokenForSystemAssignedIdentity     APIID = 1015
	APIIDAcquireTokenForUserAssignedIdentity       APIID = 1016
	APIIDAcquireTokenByFederatedIdentityCredential APIID = 1019
)

// CacheLevel identifies the cache from which a token was retrieved.
type CacheLevel int

const (
	CacheLevelNone    CacheLevel = 0
	CacheLevelUnknown CacheLevel = 1
	CacheLevelL1      CacheLevel = 2
	CacheLevelL2      CacheLevel = 3
)

// CacheRefreshReason identifies why MSAL contacted the identity provider.
type CacheRefreshReason int

const (
	CacheRefreshReasonNotApplicable        CacheRefreshReason = 0
	CacheRefreshReasonForceRefreshOrClaims CacheRefreshReason = 1
	CacheRefreshReasonNoCachedAccessToken  CacheRefreshReason = 2
	CacheRefreshReasonExpired              CacheRefreshReason = 3
	CacheRefreshReasonProactivelyRefreshed CacheRefreshReason = 4
	CacheRefreshReasonCacheDisabled        CacheRefreshReason = 5
)

// TokenSource identifies where MSAL obtained a token.
type TokenSource int

const (
	TokenSourceIdentityProvider TokenSource = 0
	TokenSourceCache            TokenSource = 1
)

// TokenType is MSAL's bounded token-type taxonomy. Values match MSAL.NET.
type TokenType int

const (
	TokenTypeBearer    TokenType = 1
	TokenTypePoP       TokenType = 2
	TokenTypeSSHCert   TokenType = 3
	TokenTypeLegacyPoP TokenType = 4
	TokenTypeExtension TokenType = 5
	TokenTypeMTLSPoP   TokenType = 6
)
