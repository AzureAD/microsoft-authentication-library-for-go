// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

// WithMtlsHTTPClient overrides how the mutual-TLS client is built for the
// IMDSv2 token leg.
//
// The default client presents the binding certificate over TLS 1.2 or later,
// which is what almost every application wants. Supply a factory only when the
// TLS handshake has to be owned by the caller, for example to add a proxy or a
// custom root store. The factory receives the binding certificate and must
// return a client that presents it, otherwise the token request is rejected.
//
// This does not affect the two plain-HTTP calls to the metadata service, which
// use the client given to [WithHTTPClient].
func WithMtlsHTTPClient(factory func(cert tls.Certificate) *http.Client) ClientOption {
	return func(c *Client) {
		c.mtlsClientFactory = factory
	}
}

// WithMtlsProofOfPossession requests a certificate-bound access token
// (token_type=mtls_pop) instead of a bearer token.
//
// The token is bound to a short-lived certificate that Azure Instance Metadata
// Service issues to this virtual machine, whose private key is created inside
// Virtualization-based Security and never leaves it. A resource that supports
// bound tokens will reject the token if it is presented on a connection that
// does not use that certificate, so a stolen token is not usable elsewhere.
//
// The returned token must be sent over a connection authenticated with the same
// certificate. Use [AuthResult.MtlsHTTPClient] to obtain a client that does
// this, and present the token with the "mtls_pop" scheme rather than "Bearer".
//
// This requires Windows with Credential Guard enabled and a host that serves
// IMDSv2. It cannot be combined with [WithRequestOverMtls].
func WithMtlsProofOfPossession() AcquireTokenOption {
	return func(o *AcquireTokenOptions) {
		o.mtlsPoP = true
	}
}

// WithRequestOverMtls requests an ordinary bearer token, but obtains it over a
// mutually authenticated connection using the certificate IMDS issues to this
// virtual machine.
//
// This hardens acquisition without changing how the token is used: the result
// is a normal bearer token that any resource accepts. Use it when the resource
// does not support certificate-bound tokens but the acquisition path should
// still be bound to this machine.
//
// This requires Windows with Credential Guard enabled and a host that serves
// IMDSv2. It cannot be combined with [WithMtlsProofOfPossession].
func WithRequestOverMtls() AcquireTokenOption {
	return func(o *AcquireTokenOptions) {
		o.overMtls = true
	}
}

// usesIMDSv2 reports whether the options select the IMDSv2 certificate path.
func (o AcquireTokenOptions) usesIMDSv2() bool {
	return o.mtlsPoP || o.overMtls
}

// stampCacheComponents records the options that change what a token is, so two
// requests that differ in them do not share a cache entry.
//
// Scope and identity alone do not describe these tokens. A bearer token
// obtained over mTLS is issued under a different policy than one obtained over
// plain HTTP; a token bound to an attested key carries a guarantee one bound to
// an unattested key does not; and a token acquired under a binding-strength
// floor was checked against a guarantee a token acquired without one was not.
// Serving any of these in place of another would silently weaken what the
// caller asked for.
//
// The component names and their values are MSAL .NET's, from
// AcquireTokenForManagedIdentityParameterBuilder, so a shared cache written by
// either library partitions the same way.
func (o AcquireTokenOptions) stampCacheComponents(params *authority.AuthParams) {
	if params.CacheKeyComponents == nil {
		params.CacheKeyComponents = map[string]string{}
	}
	// .NET records whether an attestation provider was supplied as "1" or "0".
	// Go's attestation opt-in is the same statement: WithAttestationSupport is
	// what makes the credential request carry an attestation token.
	attested := "0"
	if o.attestation {
		attested = "1"
	}
	// A proof-of-possession token bound to an attested key is not
	// interchangeable with one bound to an unattested key, even though both are
	// bound to a certificate for the same identity and scope.
	if o.mtlsPoP {
		params.CacheKeyComponents["mi_att"] = attested
	} else {
		delete(params.CacheKeyComponents, "mi_att")
	}
	// The mTLS-bearer marker carries the attestation mode as its value rather
	// than a bare flag. These tokens are ordinary bearer tokens, so the
	// authentication scheme contributes no key ID to the cache key: without the
	// mode here, nothing at all would separate an attested acquisition from an
	// unattested one.
	if o.overMtls {
		params.CacheKeyComponents["mtls_bearer"] = attested
	} else {
		delete(params.CacheKeyComponents, "mtls_bearer")
	}
	// A floor is only recorded when one was set. Writing a zero would change
	// the key shape for every caller that never asked for a floor, orphaning
	// tokens cached before this option existed.
	//
	// The value is the strength's name, not its number, because .NET stamps
	// MtlsBindingStrength.ToString() and a C# enum renders as its member name.
	if o.minStrength > MtlsBindingStrengthNone {
		params.CacheKeyComponents["mi_minstrength"] = o.minStrength.String()
	} else {
		delete(params.CacheKeyComponents, "mi_minstrength")
	}
}

// validate rejects option combinations that cannot be satisfied.
func (o AcquireTokenOptions) validate(source Source) error {
	if o.mtlsPoP && o.overMtls {
		return ErrMtlsPoPAndBearerExclusive
	}
	if !o.usesIMDSv2() {
		// Attestation applies to the binding key, which only the IMDSv2 path
		// mints. Ignoring the option here would route the request to the
		// ordinary bearer path and hand back a token with none of the
		// protection the caller asked for.
		if o.attestation {
			return ErrAttestationRequiresMtls
		}
		// A binding-strength floor is a statement about the key a token is
		// bound to. A request that binds no key cannot meet it, and accepting
		// the option silently would hand back a bearer token to a caller who
		// asked for a guarantee about binding.
		if o.minStrength > MtlsBindingStrengthNone {
			return ErrMinStrengthRequiresMtls
		}
		return nil
	}
	// Only the IMDS source issues binding certificates. The other sources have
	// no equivalent, and silently returning an ordinary bearer token would give
	// the caller a token with none of the protection they asked for.
	if source != DefaultToIMDS {
		return fmt.Errorf("%w: the source is %s", ErrMtlsPoPNotSupportedForSource, source)
	}
	if !platformSupportsMtlsPoP() {
		return ErrMtlsNotSupportedForPlatform
	}
	return nil
}

// acquireTokenForIMDSv2 runs the certificate-bound acquisition path.
//
// A cached certificate can be rejected by Entra without any local signal that
// it went stale, so a single re-mint and retry is attempted. The retry is
// bounded to one attempt: a second failure is a real error rather than a stale
// certificate, and retrying further would turn a misconfiguration into a loop
// against a rate-limited service.
func (c Client) acquireTokenForIMDSv2(ctx context.Context, resource string, o AcquireTokenOptions) (AuthResult, error) {
	// The floor is checked before anything is minted. Discovering afterwards
	// that the host cannot meet it would mean IMDS had already issued a
	// credential the caller was always going to refuse.
	if err := c.enforceMinStrength(ctx, o.minStrength); err != nil {
		return AuthResult{}, err
	}
	v := imdsV2{
		httpClient:   c.httpClient,
		keyProvider:  c.bindingKeyProvider(),
		miType:       c.miType,
		retryEnabled: c.retryPolicyEnabled,
		baseEndpoint: imdsV2BaseEndpoint(),
	}

	// Client capabilities travel in the same "claims" parameter as a
	// server-issued challenge, merged rather than concatenated, so they are
	// resolved once here and used for both attempts below. MSAL .NET performs
	// the identical merge on this leg through TokenClient's
	// ClaimsAndClientCapabilities.
	claims, err := c.claimsAndCapabilities(o)
	if err != nil {
		return AuthResult{}, err
	}

	binding, key, err := v.getBindingCertificate(ctx, o.attestation)
	if err != nil {
		return AuthResult{}, err
	}
	// binding is reassigned by the re-mint below, so the release reads the
	// variable rather than capturing the first value.
	defer func() { _ = binding.Close() }()

	tr, err := requestEntraToken(ctx, c.mtlsClient(binding.TLS), binding, resource, claims, o.mtlsPoP, c.retryPolicyEnabled)
	if err != nil {
		if !shouldRemintCertificate(err) {
			return AuthResult{}, err
		}
		certCache.evict(key)
		reminted, _, err := v.getBindingCertificate(ctx, o.attestation)
		if err != nil {
			return AuthResult{}, err
		}
		_ = binding.Close()
		binding = reminted
		tr, err = requestEntraToken(ctx, c.mtlsClient(binding.TLS), binding, resource, claims, o.mtlsPoP, c.retryPolicyEnabled)
		if err != nil {
			return AuthResult{}, err
		}
	}

	if err := verifyTokenType(tr, o.mtlsPoP); err != nil {
		return AuthResult{}, err
	}
	return c.authResultForIMDSv2(tr, binding, o)
}

// claimsAndCapabilities produces the value of the token request's claims
// parameter.
//
// Client capabilities and a server-issued challenge share that one parameter,
// so when both are present they have to be merged into a single JSON object;
// sending either alone would drop the other. authority.AuthParams already
// implements that merge for every other flow in this library, and reusing it
// keeps managed identity's spelling identical to theirs.
func (c Client) claimsAndCapabilities(o AcquireTokenOptions) (string, error) {
	// With no capabilities configured, MergeCapabilitiesAndClaims returns
	// Claims verbatim without parsing it, which is exactly the pass-through
	// this leg did before capabilities existed.
	p := c.authParams
	p.Claims = o.claims
	return p.MergeCapabilitiesAndClaims()
}

// verifyTokenType checks that the service returned the kind of token that was
// requested.
//
// Entra can answer a token_type=mtls_pop request with a bearer token, for
// example when the tenant has not enabled bound tokens. Returning that token
// would hand the caller an unbound credential while the call site believes it
// is bound, so it is rejected instead.
func verifyTokenType(tr accesstokens.TokenResponse, popRequested bool) error {
	if !popRequested {
		return nil
	}
	if !strings.EqualFold(tr.TokenType, authority.AccessTokenTypeMtlsPoP) {
		return fmt.Errorf(
			"managedidentity: a certificate-bound token was requested but the service returned a %q token; the tenant or resource may not support bound tokens",
			tr.TokenType)
	}
	return nil
}

// authResultForIMDSv2 converts the token response, caching bound tokens under a
// scheme keyed by the binding certificate so they cannot be confused with
// bearer tokens for the same resource.
func (c Client) authResultForIMDSv2(tr accesstokens.TokenResponse, binding *bindingCertificate, o AcquireTokenOptions) (AuthResult, error) {
	params := c.authParams
	if o.mtlsPoP {
		params.AuthnScheme = authority.NewMtlsPoPAuthenticationScheme(binding.Leaf)
	}
	res, err := authResultFromToken(params, tr)
	if err != nil {
		return AuthResult{}, err
	}
	if o.mtlsPoP {
		// The caller has to present this certificate when calling the resource,
		// otherwise the bound token is rejected. A copy is handed out so a
		// caller mutating it cannot corrupt the cached certificate that future
		// handshakes rely on.
		res.BindingCertificate = copyBindingCertificate(binding)
	}
	return res, nil
}

// copyBindingCertificate returns a certificate the caller can hold and mutate
// without affecting the cached one. The DER chain is deep-copied and the leaf is
// re-parsed from that copy, so the result shares no backing array with the
// cached certificate.
//
// The private key is necessarily backed by the same object, because it is a
// handle to one operating system key. The copy therefore takes a reference on
// the binding certificate so that evicting the cache entry cannot release a key
// this certificate still needs, and drops it once the caller lets the key go.
func copyBindingCertificate(binding *bindingCertificate) *tls.Certificate {
	chain := make([][]byte, len(binding.TLS.Certificate))
	for i, der := range binding.TLS.Certificate {
		chain[i] = append([]byte(nil), der...)
	}
	out := &tls.Certificate{
		Certificate: chain,
		PrivateKey:  binding.TLS.PrivateKey,
	}
	if len(chain) > 0 {
		if leaf, err := x509.ParseCertificate(chain[0]); err == nil {
			out.Leaf = leaf
		}
	}
	if out.Leaf == nil {
		// The cached chain already parsed once, so this is unreachable in
		// practice; sharing the cached leaf is still better than returning none.
		out.Leaf = binding.Leaf
	}
	if signer, ok := binding.TLS.PrivateKey.(crypto.Signer); ok {
		binding.retain()
		out.PrivateKey = newRetainedSigner(signer, binding.Close)
	}
	return out
}

// retainedSigner is the private key handed to a caller. It holds a reference on
// the cached binding certificate for exactly as long as the caller can still
// sign with it.
//
// The reference is attached to the signer rather than to the *tls.Certificate
// because callers routinely copy the certificate by value, as in
// cert := *result.BindingCertificate. A finalizer on the certificate pointer
// would then see that pointer become unreachable while the value copy is still
// in use, and release the key underneath the caller. The private key survives
// every such copy, so it is the only place the reference can safely live. This
// mirrors what SafeHandle does for the same certificate in MSAL .NET.
type retainedSigner struct {
	crypto.Signer
	release func() error
}

func newRetainedSigner(signer crypto.Signer, release func() error) *retainedSigner {
	held := &retainedSigner{Signer: signer, release: release}
	runtime.SetFinalizer(held, func(h *retainedSigner) { _ = h.release() })
	return held
}

// mtlsClient builds the client used for the IMDSv2 token leg, honouring
// [WithMtlsHTTPClient] when the caller supplied a factory.
func (c Client) mtlsClient(cert tls.Certificate) *http.Client {
	if c.mtlsClientFactory != nil {
		return c.mtlsClientFactory(cert)
	}
	return mtlsHTTPClient(cert)
}

// imdsV2BaseEndpoint returns the metadata service root.
//
// AZURE_POD_IDENTITY_AUTHORITY_HOST redirects the metadata calls at a pod
// identity sidecar, which is how AKS presents a managed identity to a
// container. It is honoured here for the same reason IMDSv1 honours it.
func imdsV2BaseEndpoint() string {
	if host := os.Getenv(azurePodIdentityAuthorityHostEnvVar); host != "" {
		return strings.TrimSuffix(host, "/")
	}
	return imdsV2DefaultBaseEndpoint
}

// bindingKeyProvider returns the key provider for this client. It is
// indirected through a field so the flow tests can supply a software key.
func (c Client) bindingKeyProvider() keyProvider {
	if c.keyProvider != nil {
		return c.keyProvider
	}
	return newKeyProvider()
}
