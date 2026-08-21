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

	// BindingCertificate is the certificate the assertion is bound to, presented as the client
	// certificate on the mutual-TLS handshake when the request is an mTLS proof-of-possession
	// request. It may be nil, in which case the binding certificate is resolved as it is for a
	// plain assertion credential. Its PrivateKey may be any crypto.Signer, including a
	// non-exportable platform key.
	BindingCertificate *tls.Certificate
}

// AssertionRequestOptions has information required to generate a client assertion
type AssertionRequestOptions struct {
	// ClientID identifies the application for which an assertion is requested. Used as the assertion's "iss" and "sub" claims.
	ClientID string

	// TokenEndpoint is the intended token endpoint. Used as the assertion's "aud" claim.
	TokenEndpoint string

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
