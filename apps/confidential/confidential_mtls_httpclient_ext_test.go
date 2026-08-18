// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential_test

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// TestWithMtlsHTTPClientIsCallableExternally is a compile-time regression test for the documented
// mTLS escape hatch.
//
// This file is package confidential_test, so it is a genuine external consumer: it can only name
// exported identifiers of apps/confidential and cannot import anything under apps/internal. The
// option previously took func(tls.Certificate) ops.HTTPClient, where ops.HTTPClient was a type alias
// for an interface declared in apps/internal/oauth/ops/internal/comm. A type alias does not launder
// internal-ness, and Go function types are invariant in their result type, so no external module
// could construct a value of that function type — the documented escape hatch did not compile for
// consumers.
//
// Passing a plain func(tls.Certificate) *http.Client literal below is the whole point: if the
// signature ever regresses to an internal type, this file stops compiling.
//
// MSAL .NET's equivalent, IMsalMtlsHttpClientFactory with
// GetHttpClient(X509Certificate2) -> HttpClient, is public on every target framework, so this is also
// a parity fix.
func TestWithMtlsHTTPClientIsCallableExternally(t *testing.T) {
	called := false
	factory := func(cert tls.Certificate) *http.Client {
		called = true
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
				},
			},
		}
	}

	cred, err := confidential.NewCredFromSecret("secret")
	if err != nil {
		t.Fatalf("NewCredFromSecret() failed: %s", err)
	}
	if _, err := confidential.New(
		"https://login.microsoftonline.com/tenant",
		"client-id",
		cred,
		confidential.WithMtlsHTTPClient(factory),
	); err != nil {
		t.Fatalf("New() with WithMtlsHTTPClient failed: %s", err)
	}

	// The option only installs the factory; nothing invokes it until an mTLS PoP token request runs.
	if called {
		t.Error("the factory must not be invoked at construction time")
	}

	// A nil factory must be accepted and must leave MSAL on its built-in client builder.
	if _, err := confidential.New(
		"https://login.microsoftonline.com/tenant",
		"client-id",
		cred,
		confidential.WithMtlsHTTPClient(nil),
	); err != nil {
		t.Fatalf("New() with a nil mTLS factory failed: %s", err)
	}
}
