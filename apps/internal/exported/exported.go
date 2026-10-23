// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// package exported contains internal types that are re-exported from a public package
package exported

import "crypto/tls"

// SignedAssertion is a client assertion together with the certificate that assertion is bound to.
// Returning both from one callback keeps them paired: the assertion and the certificate that proves
// possession of it can't be mismatched across a certificate rotation.
type SignedAssertion struct {
	// Assertion is the client assertion, the same value a plain assertion callback returns.
	Assertion string

	// BindingCertificate is the certificate the assertion is bound to. When non-nil, MSAL presents it
	// as the TLS client certificate and sends Assertion with the jwt-pop assertion type. The final
	// access token is still Bearer unless the acquisition requests mTLS proof-of-possession; Bearer
	// results don't expose this certificate as a token-binding capability. A nil certificate keeps
	// jwt-bearer and the regular token endpoint, except that explicit mTLS options fail closed when
	// the callback omits it. PrivateKey may be any crypto.Signer, including a non-exportable platform
	// key.
	BindingCertificate *tls.Certificate
}

// AssertionRequestOptions has information required to generate a client assertion
type AssertionRequestOptions struct {
	// ClientID identifies the application for which an assertion is requested. Used as the assertion's "iss" and "sub" claims.
	ClientID string

	// TokenEndpoint is the resolved endpoint known when the callback runs. Explicit mTLS requests
	// receive the mtlsauth endpoint. For implicit mTLS, certificate presence is learned from the
	// callback itself, so this is the regular resolved endpoint and MSAL selects the corresponding
	// mtlsauth wire endpoint after the callback returns.
	TokenEndpoint string

	// TenantID is the tenant selected for this request, including a per-request tenant override.
	TenantID string

	// Authority is the canonical authority configured for this request. Unlike TokenEndpoint, it is
	// never rewritten to an mTLS wire endpoint.
	Authority string

	// Claims contains the per-request claims challenge, if any.
	Claims string

	// ClientCapabilities contains the client capabilities configured on the application.
	ClientCapabilities []string

	// CorrelationID identifies this authentication request for diagnostics.
	CorrelationID string

	// FMIPath is the federated managed identity path for the current request, if any.
	// Assertion providers can use this to scope the credential they return.
	FMIPath string
}

// TokenProviderParameters is the authentication parameters passed to token providers
type TokenProviderParameters struct {
	// Claims contains any additional claims requested for the token
	Claims string
	// CorrelationID of the authentication request
	CorrelationID string
	// Scopes requested for the token
	Scopes []string
	// TenantID identifies the tenant in which to authenticate
	TenantID string
}

// TokenProviderResult is the authentication result returned by custom token providers
type TokenProviderResult struct {
	// AccessToken is the requested token
	AccessToken string
	// ExpiresInSeconds is the lifetime of the token in seconds
	ExpiresInSeconds int
	// RefreshInSeconds indicates the suggested	time to refresh the token, if any
	RefreshInSeconds int
}
