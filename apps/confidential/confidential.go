// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/*
Package confidential provides a client for authentication of "confidential" applications.
A "confidential" application is defined as an app that run on servers. They are considered
difficult to access and for that reason capable of keeping an application secret.
Confidential clients can hold configuration-time secrets.
*/
package confidential

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/exported"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/options"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
)

/*
Design note:

confidential.Client uses base.Client as an embedded type. base.Client statically assigns its attributes
during creation. As it doesn't have any pointers in it, anything borrowed from it, such as
Base.AuthParams is a copy that is free to be manipulated here.

Duplicate Calls shared between public.Client and this package:
There is some duplicate call options provided here that are the same as in public.Client . This
is a design choices. Go proverb(https://www.youtube.com/watch?v=PAAkCSZUG1c&t=9m28s):
"a little copying is better than a little dependency". Yes, we could have another package with
shared options (fail).  That divides like 2 options from all others which makes the user look
through more docs.  We can have all clients in one package, but I think separate packages
here makes for better naming (public.Client vs client.PublicClient).  So I chose a little
duplication.

.Net People, Take note on X509:
This uses x509.Certificates and private keys. x509 does not store private keys. .Net
has a x509.Certificate2 abstraction that has private keys, but that just a strange invention.
As such I've put a PEM decoder into here.
*/

// TODO(msal): This should have example code for each method on client using Go's example doc framework.
// base usage details should be include in the package documentation.

// clientClaimsCacheKey is the CacheKeyComponents key used to partition the token cache by
// client-originated claims (see WithClaimsFromClient). The component value is the raw claims string.
const clientClaimsCacheKey = "client_claims"

// AuthResult contains the results of one token acquisition operation.
// For details see https://aka.ms/msal-net-authenticationresult
type AuthResult = base.AuthResult

type AuthenticationScheme = authority.AuthenticationScheme

type Account = shared.Account

type TokenSource = base.TokenSource

const (
	TokenSourceIdentityProvider = base.TokenSourceIdentityProvider
	TokenSourceCache            = base.TokenSourceCache
)

// CertFromPEM converts a PEM file (.pem or .key) for use with [NewCredFromCert]. The file
// must contain the public certificate and the unencrypted private key.
// Multiple certs are due to certificate chaining for use cases like TLS that sign from root to leaf.
//
// Encrypted PEM private keys are not supported. Legacy RFC 1423 encrypted PEM blocks (identified
// by a DEK-Info header, e.g. "DEK-Info: DES-EDE3-CBC,...") rely on a weak key derivation function
// (a single MD5 iteration) and obsolete DES/3DES ciphers, so CertFromPEM rejects them with an
// error instead of decrypting them. Provide the private key unencrypted and protect it with
// filesystem permissions; you can remove legacy encryption with, for example:
//
//	openssl pkcs8 -topk8 -nocrypt -in legacy.key -out key.pem
//
// The password parameter is retained for backward compatibility and is ignored.
func CertFromPEM(pemData []byte, password string) ([]*x509.Certificate, crypto.PrivateKey, error) {
	var certs []*x509.Certificate
	var priv crypto.PrivateKey
	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}

		if _, encrypted := block.Headers["DEK-Info"]; encrypted {
			return nil, nil, fmt.Errorf("legacy RFC 1423 encrypted PEM blocks are not supported because they use a weak key derivation function (single MD5 iteration) and obsolete DES/3DES ciphers; provide the private key unencrypted (e.g. `openssl pkcs8 -topk8 -nocrypt -in legacy.key -out key.pem`) and protect it with filesystem permissions")
		}

		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("block labelled 'CERTIFICATE' could not be parsed by x509: %v", err)
			}
			certs = append(certs, cert)
		case "PRIVATE KEY":
			if priv != nil {
				return nil, nil, errors.New("found multiple private key blocks")
			}

			var err error
			priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("could not decode private key: %v", err)
			}
		case "RSA PRIVATE KEY":
			if priv != nil {
				return nil, nil, errors.New("found multiple private key blocks")
			}
			var err error
			priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("could not decode private key: %v", err)
			}
		}
		pemData = rest
	}

	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no certificates found")
	}

	if priv == nil {
		return nil, nil, fmt.Errorf("no private key found")
	}

	return certs, priv, nil
}

// AssertionRequestOptions has required information for client assertion claims
type AssertionRequestOptions = exported.AssertionRequestOptions

// Credential represents the credential used in confidential client flows.
type Credential struct {
	secret string

	cert *x509.Certificate
	key  crypto.PrivateKey
	x5c  []string

	// signerOnly is set when key can't be exported as an *rsa.PrivateKey, which means MSAL must sign
	// through its crypto.Signer interface. See NewCredFromTLSCertificate.
	signerOnly bool

	assertionCallback func(context.Context, AssertionRequestOptions) (string, error)

	tokenProvider func(context.Context, TokenProviderParameters) (TokenProviderResult, error)
}

// toInternal returns the accesstokens.Credential that is used internally. The current structure of the
// code requires that client.go, requests.go and confidential.go share a credential type without
// having import recursion. That requires the type used between is in a shared package. Therefore
// we have this.
func (c Credential) toInternal() (*accesstokens.Credential, error) {
	if c.secret != "" {
		return &accesstokens.Credential{Secret: c.secret}, nil
	}
	if c.cert != nil {
		if c.key == nil {
			return nil, errors.New("missing private key for certificate")
		}
		return &accesstokens.Credential{Cert: c.cert, Key: c.key, X5c: c.x5c, SignerOnly: c.signerOnly}, nil
	}
	if c.key != nil {
		return nil, errors.New("missing certificate for private key")
	}
	if c.assertionCallback != nil {
		return &accesstokens.Credential{AssertionCallback: c.assertionCallback}, nil
	}
	if c.tokenProvider != nil {
		return &accesstokens.Credential{TokenProvider: c.tokenProvider}, nil
	}
	return nil, errors.New("invalid credential")
}

// NewCredFromSecret creates a Credential from a secret.
func NewCredFromSecret(secret string) (Credential, error) {
	if secret == "" {
		return Credential{}, errors.New("secret can't be empty string")
	}
	return Credential{secret: secret}, nil
}

// NewCredFromAssertionCallback creates a Credential that invokes a callback to get assertions
// authenticating the application. The callback must be thread safe.
func NewCredFromAssertionCallback(callback func(context.Context, AssertionRequestOptions) (string, error)) Credential {
	return Credential{assertionCallback: callback}
}

// NewCredFromCert creates a Credential from a certificate or chain of certificates and an RSA private key
// as returned by [CertFromPEM].
//
// key may also be a [crypto.Signer] whose public key is an *rsa.PublicKey. That's how a non-exportable
// key such as a Windows KeyGuard (VBS-isolated) or other CNG/HSM-backed key surfaces in Go. MSAL signs
// client assertions through the signer, so such a credential works in every flow.
// [NewCredFromTLSCertificate] is the more direct constructor for these keys.
func NewCredFromCert(certs []*x509.Certificate, key crypto.PrivateKey) (Credential, error) {
	cred := Credential{key: key}
	var k *rsa.PublicKey
	switch t := key.(type) {
	case *rsa.PrivateKey:
		k = &t.PublicKey
	case crypto.Signer:
		pub, ok := t.Public().(*rsa.PublicKey)
		if !ok {
			return cred, errors.New("key must be an RSA key")
		}
		k = pub
		cred.signerOnly = true
	default:
		return cred, errors.New("key must be an RSA key")
	}
	for _, cert := range certs {
		if cert == nil {
			// not returning an error here because certs may still contain a sufficient cert/key pair
			continue
		}
		certKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if ok && k.E == certKey.E && k.N.Cmp(certKey.N) == 0 {
			// We know this is the signing cert because its public key matches the given private key.
			// This cert must be first in x5c.
			cred.cert = cert
			cred.x5c = append([]string{base64.StdEncoding.EncodeToString(cert.Raw)}, cred.x5c...)
		} else {
			cred.x5c = append(cred.x5c, base64.StdEncoding.EncodeToString(cert.Raw))
		}
	}
	if cred.cert == nil {
		return cred, errors.New("key doesn't match any certificate")
	}
	return cred, nil
}

// NewCredFromTLSCertificate creates a Credential from a [tls.Certificate] whose PrivateKey is any
// [crypto.Signer]. This is the entry point for keys whose private material can never be exported,
// such as Windows KeyGuard (VBS-isolated) keys imported with PKCS12_VIRTUAL_ISOLATION_KEY, or other
// CNG/HSM-backed keys: the signer stays in its protected store and is invoked only to sign.
//
// The credential works in every flow. mTLS proof-of-possession (see [WithMtlsProofOfPossession])
// presents the certificate on the TLS handshake and sends no client_assertion; every other flow has
// the signer sign the assertion. Because the service accepts only RSA client assertions, a signer
// whose public key isn't an *rsa.PublicKey is limited to mTLS proof-of-possession.
//
// cert.Certificate must hold the DER-encoded chain leaf first, as [tls.Certificate] requires. cert.Leaf
// is used when it matches that leaf; otherwise the leaf is parsed from cert.Certificate[0].
func NewCredFromTLSCertificate(cert tls.Certificate) (Credential, error) {
	if len(cert.Certificate) == 0 || len(cert.Certificate[0]) == 0 {
		return Credential{}, errors.New("tls.Certificate must contain at least one certificate")
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return Credential{}, errors.New("tls.Certificate.PrivateKey must implement crypto.Signer")
	}
	leaf := cert.Leaf
	if leaf == nil || !bytes.Equal(leaf.Raw, cert.Certificate[0]) {
		var err error
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return Credential{}, fmt.Errorf("could not parse the leaf certificate: %v", err)
		}
	}
	// every public key type x509 can parse implements Equal, added in Go 1.15
	pub, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(signer.Public()) {
		return Credential{}, errors.New("key doesn't match the leaf certificate")
	}
	cred := Credential{cert: leaf, key: cert.PrivateKey}
	// tls.Certificate stores the chain leaf first, which is the order x5c requires
	for _, der := range cert.Certificate {
		cred.x5c = append(cred.x5c, base64.StdEncoding.EncodeToString(der))
	}
	if _, ok := cert.PrivateKey.(*rsa.PrivateKey); !ok {
		cred.signerOnly = true
	}
	return cred, nil
}

// TokenProviderParameters is the authentication parameters passed to token providers
type TokenProviderParameters = exported.TokenProviderParameters

// TokenProviderResult is the authentication result returned by custom token providers
type TokenProviderResult = exported.TokenProviderResult

// NewCredFromTokenProvider creates a Credential from a function that provides access tokens. The function
// must be concurrency safe. This is intended only to allow the Azure SDK to cache MSI tokens. It isn't
// useful to applications in general because the token provider must implement all authentication logic.
func NewCredFromTokenProvider(provider func(context.Context, TokenProviderParameters) (TokenProviderResult, error)) Credential {
	return Credential{tokenProvider: provider}
}

// AutoDetectRegion instructs MSAL Go to auto detect region for Azure regional token service.
func AutoDetectRegion() string {
	return "TryAutoDetect"
}

// Client is a representation of authentication client for confidential applications as defined in the
// package doc. A new Client should be created PER SERVICE USER.
// For more information, visit https://docs.microsoft.com/azure/active-directory/develop/msal-client-applications
type Client struct {
	base base.Client
	cred *accesstokens.Credential
}

// clientOptions are optional settings for New(). These options are set using various functions
// returning Option calls.
type clientOptions struct {
	accessor                          cache.ExportReplace
	authority, azureRegion            string
	capabilities                      []string
	disableInstanceDiscovery, sendX5C bool
	httpClient                        ops.HTTPClient
	mtlsHTTPClientFactory             ops.MtlsClientFactory
}

// Option is an optional argument to New().
type Option func(o *clientOptions)

// WithCache provides an accessor that will read and write authentication data to an externally managed cache.
func WithCache(accessor cache.ExportReplace) Option {
	return func(o *clientOptions) {
		o.accessor = accessor
	}
}

// WithClientCapabilities allows configuring one or more client capabilities such as "CP1"
func WithClientCapabilities(capabilities []string) Option {
	return func(o *clientOptions) {
		// there's no danger of sharing the slice's underlying memory with the application because
		// this slice is simply passed to base.WithClientCapabilities, which copies its data
		o.capabilities = capabilities
	}
}

// WithHTTPClient allows for a custom HTTP client to be set.
//
// A plain HTTP client cannot carry the client certificate required for mTLS proof-of-possession
// (see [WithMtlsProofOfPossession]); use [WithMtlsHTTPClient] to override the mTLS transport.
//
// On that mutual-TLS leg MSAL installs the binding certificate on a copy of this client's transport,
// which carries the caller's configuration across only when Transport is an [*http.Transport] - the
// type that holds Proxy, DialContext and TLSClientConfig (including RootCAs). Shapes that cannot
// carry the certificate into the handshake are rejected rather than quietly rerouted, and mTLS token
// requests then fail with an error naming [WithMtlsHTTPClient]:
//
//   - a custom [http.RoundTripper], such as a tracing, retry, pinning or request-signing wrapper,
//     because a TLS client certificate can only be installed through [*http.Transport], and
//     substituting [http.DefaultTransport] would send a credential-bearing request outside whatever
//     proxy, audit or egress controls that wrapper enforces;
//   - an [*http.Transport] that sets DialTLS or DialTLSContext, because net/http then runs the
//     handshake through that hook and ignores TLSClientConfig entirely.
//
// A client with no Transport is fine: there is no caller network path to lose, so the mutual-TLS leg
// builds on a clone of [http.DefaultTransport]. That clone is checked for TLS dial hooks too, since
// [http.DefaultTransport] is an exported package-level variable anything in the process can patch.
//
// Redirects are refused on the mutual-TLS leg unless this client sets CheckRedirect. A 307 or 308
// would replay the token request body, which carries a client credential, and present the binding
// certificate to the redirect target. Setting CheckRedirect here takes ownership of that decision.
func WithHTTPClient(httpClient ops.HTTPClient) Option {
	return func(o *clientOptions) {
		o.httpClient = httpClient
	}
}

// WithMtlsHTTPClient overrides how the mutual-TLS client is built for mTLS proof-of-possession
// token requests (see [WithMtlsProofOfPossession]). The factory receives the binding certificate and
// must return an [http.Client] whose transport presents that certificate during the TLS handshake.
//
// This is an escape hatch for callers who must own the TLS handshake themselves. It isn't needed for
// non-exportable keys: a [crypto.Signer] supplied through [NewCredFromTLSCertificate] is passed
// straight to the built-in transport, which crypto/tls signs with on both TLS 1.2 and 1.3. When
// unset, MSAL auto-builds and caches an mTLS client per certificate thumbprint.
func WithMtlsHTTPClient(factory func(cert tls.Certificate) *http.Client) Option {
	return func(o *clientOptions) {
		if factory == nil {
			o.mtlsHTTPClientFactory = nil
			return
		}
		o.mtlsHTTPClientFactory = func(cert tls.Certificate) ops.HTTPClient {
			client := factory(cert)
			if client == nil {
				// Return an untyped nil rather than an interface wrapping a nil *http.Client, so
				// the internal nil check sees it instead of caching a client that panics on Do.
				return nil
			}
			return client
		}
	}
}

// WithX5C specifies if x5c claim(public key of the certificate) should be sent to STS to enable Subject Name Issuer Authentication.
func WithX5C() Option {
	return func(o *clientOptions) {
		o.sendX5C = true
	}
}

// WithInstanceDiscovery set to false to disable authority validation (to support private cloud scenarios)
func WithInstanceDiscovery(enabled bool) Option {
	return func(o *clientOptions) {
		o.disableInstanceDiscovery = !enabled
	}
}

// WithAzureRegion sets the region(preferred) or Confidential.AutoDetectRegion() for auto detecting region.
// Region names as per https://azure.microsoft.com/en-ca/global-infrastructure/geographies/.
// See https://aka.ms/region-map for more details on region names.
// The region value should be short region name for the region where the service is deployed.
// For example "centralus" is short name for region Central US.
// Not all auth flows can use the regional token service.
// Service To Service (client credential flow) tokens can be obtained from the regional service.
// Requires configuration at the tenant level.
// Auto-detection works on a limited number of Azure artifacts (VMs, Azure functions).
// If auto-detection fails, the non-regional endpoint will be used.
// If an invalid region name is provided, the non-regional endpoint MIGHT be used or the token request MIGHT fail.
func WithAzureRegion(val string) Option {
	return func(o *clientOptions) {
		if val != "" {
			o.azureRegion = val
		}
	}
}

// New is the constructor for Client. authority is the URL of a token authority such as "https://login.microsoftonline.com/<your tenant>".
// If the Client will connect directly to AD FS, use "adfs" for the tenant. clientID is the application's client ID (also called its
// "application ID").
func New(authority, clientID string, cred Credential, options ...Option) (Client, error) {
	internalCred, err := cred.toInternal()
	if err != nil {
		return Client{}, err
	}
	autoEnabledRegion := os.Getenv("MSAL_FORCE_REGION")
	opts := clientOptions{
		authority: authority,
		// if the caller specified a token provider, it will handle all details of authentication, using Client only as a token cache
		disableInstanceDiscovery: cred.tokenProvider != nil,
		httpClient:               shared.DefaultClient,
		azureRegion:              autoEnabledRegion,
	}
	for _, o := range options {
		o(&opts)
	}
	if strings.EqualFold(opts.azureRegion, "DisableMsalForceRegion") {
		opts.azureRegion = ""
	}

	baseOpts := []base.Option{
		base.WithCacheAccessor(opts.accessor),
		base.WithClientCapabilities(opts.capabilities),
		base.WithInstanceDiscovery(!opts.disableInstanceDiscovery),
		base.WithRegionDetection(opts.azureRegion),
		base.WithX5C(opts.sendX5C),
	}
	tokenClient := oauth.New(opts.httpClient)
	if opts.mtlsHTTPClientFactory != nil {
		tokenClient.SetMtlsClientFactory(opts.mtlsHTTPClientFactory)
	}
	base, err := base.New(clientID, opts.authority, tokenClient, baseOpts...)
	if err != nil {
		return Client{}, err
	}
	base.AuthParams.IsConfidentialClient = true

	return Client{base: base, cred: internalCred}, nil
}

// authCodeURLOptions contains options for AuthCodeURL
type authCodeURLOptions struct {
	claims, loginHint, tenantID, domainHint, prompt string
}

// AuthCodeURLOption is implemented by options for AuthCodeURL
type AuthCodeURLOption interface {
	authCodeURLOption()
}

// AuthCodeURL creates a URL used to acquire an authorization code. Users need to call CreateAuthorizationCodeURLParameters and pass it in.
//
// Options: [WithClaims], [WithDomainHint], [WithLoginHint], [WithTenantID], [WithPrompt]
func (cca Client) AuthCodeURL(ctx context.Context, clientID, redirectURI string, scopes []string, opts ...AuthCodeURLOption) (string, error) {
	o := authCodeURLOptions{}
	if err := options.ApplyOptions(&o, opts); err != nil {
		return "", err
	}
	ap, err := cca.base.AuthParams.WithTenant(o.tenantID)
	if err != nil {
		return "", err
	}
	ap.Claims = o.claims
	ap.LoginHint = o.loginHint
	ap.DomainHint = o.domainHint
	ap.Prompt = o.prompt
	return cca.base.AuthCodeURL(ctx, clientID, redirectURI, scopes, ap)
}

// WithLoginHint pre-populates the login prompt with a username.
func WithLoginHint(username string) interface {
	AuthCodeURLOption
	options.CallOption
} {
	return struct {
		AuthCodeURLOption
		options.CallOption
	}{
		CallOption: options.NewCallOption(
			func(a any) error {
				switch t := a.(type) {
				case *authCodeURLOptions:
					t.loginHint = username
				default:
					return fmt.Errorf("unexpected options type %T", a)
				}
				return nil
			},
		),
	}
}

// WithDomainHint adds the IdP domain as domain_hint query parameter in the auth url.
func WithDomainHint(domain string) interface {
	AuthCodeURLOption
	options.CallOption
} {
	return struct {
		AuthCodeURLOption
		options.CallOption
	}{
		CallOption: options.NewCallOption(
			func(a any) error {
				switch t := a.(type) {
				case *authCodeURLOptions:
					t.domainHint = domain
				default:
					return fmt.Errorf("unexpected options type %T", a)
				}
				return nil
			},
		),
	}
}

// WithPrompt adds prompt query parameter in the auth url.
func WithPrompt(prompt shared.Prompt) interface {
	AuthCodeURLOption
	options.CallOption
} {
	return struct {
		AuthCodeURLOption
		options.CallOption
	}{
		CallOption: options.NewCallOption(
			func(a any) error {
				switch t := a.(type) {
				case *authCodeURLOptions:
					t.prompt = prompt.String()
				default:
					return fmt.Errorf("unexpected options type %T", a)
				}
				return nil
			},
		),
	}
}

// WithClaims sets additional claims to request for the token, such as those required by conditional access policies.
// Use this option when Azure AD returned a claims challenge for a prior request. The argument must be decoded.
// This option is valid for any token acquisition method.
func WithClaims(claims string) interface {
	AcquireByAuthCodeOption
	AcquireByCredentialOption
	AcquireOnBehalfOfOption
	AcquireByUsernamePasswordOption
	AcquireSilentOption
	AuthCodeURLOption
	AcquireByUserFICOption
	options.CallOption
} {
	return struct {
		AcquireByAuthCodeOption
		AcquireByCredentialOption
		AcquireOnBehalfOfOption
		AcquireByUsernamePasswordOption
		AcquireSilentOption
		AuthCodeURLOption
		AcquireByUserFICOption
		options.CallOption
	}{
		CallOption: options.NewCallOption(
			func(a any) error {
				switch t := a.(type) {
				case *acquireTokenByAuthCodeOptions:
					t.claims = claims
				case *acquireTokenByCredentialOptions:
					t.claims = claims
				case *acquireTokenOnBehalfOfOptions:
					t.claims = claims
				case *acquireTokenByUsernamePasswordOptions:
					t.claims = claims
				case *acquireTokenSilentOptions:
					t.claims = claims
				case *authCodeURLOptions:
					t.claims = claims
				case *acquireTokenByUserFICOptions:
					t.claims = claims
				default:
					return fmt.Errorf("unexpected options type %T", a)
				}
				return nil
			},
		),
	}
}

// WithClaimsFromClient specifies client-originated claims (a JSON object) to include in the token
// request.
//
// Unlike [WithClaims] (for server-issued claims challenges, which bypass the token cache), tokens
// acquired with client claims ARE cached and the cache entry is keyed on the claims value. Different
// claims values produce separate cache entries, so callers should pass stable, non-dynamic values to
// avoid unbounded cache growth. The exact same string MUST be included on every request: the raw
// string is used verbatim as part of the cache key (MSAL does not normalize it), so omitting it or
// changing it on a later call silently moves to a different cache partition.
//
// The claims are sent to the authority as the standard OAuth "claims" body parameter (merged with any
// server-issued claims and client capabilities); they are not embedded in the client assertion JWT.
//
// The argument must be a JSON object, but the confidential client does not enforce this locally in all
// cases: the value is forwarded to the authority verbatim and is validated locally only when it is
// merged with server-issued claims or client capabilities. Otherwise a malformed or non-object value
// is not rejected locally and instead surfaces as a server-side error. An empty or whitespace-only
// value is ignored.
func WithClaimsFromClient(claims string) interface {
	AcquireByAuthCodeOption
	AcquireByCredentialOption
	AcquireOnBehalfOfOption
	AcquireByUsernamePasswordOption
	AcquireSilentOption
	AcquireByUserFICOption
	options.CallOption
} {
	return struct {
		AcquireByAuthCodeOption
		AcquireByCredentialOption
		AcquireOnBehalfOfOption
		AcquireByUsernamePasswordOption
		AcquireSilentOption
		AcquireByUserFICOption
		options.CallOption
	}{
		CallOption: options.NewCallOption(
			func(a any) error {
				if strings.TrimSpace(claims) == "" {
					// Ignore empty/whitespace claims so callers can pass a value unconditionally.
					return nil
				}
				addCacheKey := func(m *map[string]string) {
					if *m == nil {
						*m = make(map[string]string)
					}
					(*m)[clientClaimsCacheKey] = claims
				}
				switch t := a.(type) {
				case *acquireTokenByAuthCodeOptions:
					t.clientClaims = claims
					addCacheKey(&t.cacheKeyComponents)
				case *acquireTokenByCredentialOptions:
					t.clientClaims = claims
					addCacheKey(&t.cacheKeyComponents)
				case *acquireTokenOnBehalfOfOptions:
					t.clientClaims = claims
					addCacheKey(&t.cacheKeyComponents)
				case *acquireTokenByUsernamePasswordOptions:
					t.clientClaims = claims
					addCacheKey(&t.cacheKeyComponents)
				case *acquireTokenSilentOptions:
					t.clientClaims = claims
					addCacheKey(&t.cacheKeyComponents)
				case *acquireTokenByUserFICOptions:
					t.clientClaims = claims
					addCacheKey(&t.cacheKeyComponents)
				default:
					return fmt.Errorf("unexpected options type %T", a)
				}
				return nil
			},
		),
	}
}

// WithAuthenticationScheme is an extensibility mechanism designed to be used only by Azure SDK
// clients.
//
// It cannot be combined with [WithMtlsProofOfPossession] on [Client.AcquireTokenByCredential];
// supplying both returns an error rather than one option silently overriding the other.
func WithAuthenticationScheme(authnScheme AuthenticationScheme) interface {
	AcquireSilentOption
	AcquireByCredentialOption
	options.CallOption
} {
	return struct {
		AcquireSilentOption
		AcquireByCredentialOption
		options.CallOption
	}{
		CallOption: options.NewCallOption(
			func(a any) error {
				switch t := a.(type) {
				case *acquireTokenSilentOptions:
					t.authnScheme = authnScheme
				case *acquireTokenByCredentialOptions:
					t.authnScheme = authnScheme
				default:
					return fmt.Errorf("unexpected options type %T", a)
				}
				return nil
			},
		),
	}
}

// WithTenantID specifies a tenant for a single authentication. It may be different than the tenant set in [New].
// This option is valid for any token acquisition method.
func WithTenantID(tenantID string) interface {
	AcquireByAuthCodeOption
	AcquireByCredentialOption
	AcquireOnBehalfOfOption
	AcquireByUsernamePasswordOption
	AcquireSilentOption
	AuthCodeURLOption
	AcquireByUserFICOption
	options.CallOption
} {
	return struct {
		AcquireByAuthCodeOption
		AcquireByCredentialOption
		AcquireOnBehalfOfOption
		AcquireByUsernamePasswordOption
		AcquireSilentOption
		AuthCodeURLOption
		AcquireByUserFICOption
		options.CallOption
	}{
		CallOption: options.NewCallOption(
			func(a any) error {
				switch t := a.(type) {
				case *acquireTokenByAuthCodeOptions:
					t.tenantID = tenantID
				case *acquireTokenByCredentialOptions:
					t.tenantID = tenantID
				case *acquireTokenOnBehalfOfOptions:
					t.tenantID = tenantID
				case *acquireTokenByUsernamePasswordOptions:
					t.tenantID = tenantID
				case *acquireTokenSilentOptions:
					t.tenantID = tenantID
				case *authCodeURLOptions:
					t.tenantID = tenantID
				case *acquireTokenByUserFICOptions:
					t.tenantID = tenantID
				default:
					return fmt.Errorf("unexpected options type %T", a)
				}
				return nil
			},
		),
	}
}

// acquireTokenSilentOptions are all the optional settings to an AcquireTokenSilent() call.
// These are set by using various AcquireTokenSilentOption functions.
type acquireTokenSilentOptions struct {
	account            Account
	claims, tenantID   string
	clientClaims       string
	authnScheme        AuthenticationScheme
	cacheKeyComponents map[string]string
}

// AcquireSilentOption is implemented by options for AcquireTokenSilent
type AcquireSilentOption interface {
	acquireSilentOption()
}

// WithSilentAccount uses the passed account during an AcquireTokenSilent() call.
func WithSilentAccount(account Account) interface {
	AcquireSilentOption
	options.CallOption
} {
	return struct {
		AcquireSilentOption
		options.CallOption
	}{
		CallOption: options.NewCallOption(
			func(a any) error {
				switch t := a.(type) {
				case *acquireTokenSilentOptions:
					t.account = account
				default:
					return fmt.Errorf("unexpected options type %T", a)
				}
				return nil
			},
		),
	}
}

// AcquireTokenSilent acquires a token from either the cache or using a refresh token.
//
// Options: [WithClaims], [WithClaimsFromClient], [WithSilentAccount], [WithTenantID]
func (cca Client) AcquireTokenSilent(ctx context.Context, scopes []string, opts ...AcquireSilentOption) (AuthResult, error) {
	o := acquireTokenSilentOptions{}
	if err := options.ApplyOptions(&o, opts); err != nil {
		return AuthResult{}, err
	}

	if o.claims != "" {
		return AuthResult{}, errors.New("call another AcquireToken method to request a new token having these claims")
	}

	// For service principal scenarios, require WithSilentAccount for public API
	if o.account.IsZero() {
		return AuthResult{}, errors.New("WithSilentAccount option is required")
	}

	silentParameters := base.AcquireTokenSilentParameters{
		Scopes:             scopes,
		Account:            o.account,
		RequestType:        accesstokens.ATConfidential,
		Credential:         cca.cred,
		IsAppCache:         o.account.IsZero(),
		TenantID:           o.tenantID,
		AuthnScheme:        o.authnScheme,
		Claims:             o.claims,
		ClientClaims:       o.clientClaims,
		CacheKeyComponents: o.cacheKeyComponents,
	}

	return cca.acquireTokenSilentInternal(ctx, silentParameters)
}

// acquireTokenSilentInternal is the internal implementation shared by AcquireTokenSilent and AcquireTokenByCredential
func (cca Client) acquireTokenSilentInternal(ctx context.Context, silentParameters base.AcquireTokenSilentParameters) (AuthResult, error) {

	return cca.base.AcquireTokenSilent(ctx, silentParameters)
}

// acquireTokenByUsernamePasswordOptions contains optional configuration for AcquireTokenByUsernamePassword
type acquireTokenByUsernamePasswordOptions struct {
	claims, tenantID   string
	clientClaims       string
	authnScheme        AuthenticationScheme
	cacheKeyComponents map[string]string
}

// AcquireByUsernamePasswordOption is implemented by options for AcquireTokenByUsernamePassword
type AcquireByUsernamePasswordOption interface {
	acquireByUsernamePasswordOption()
}

// AcquireTokenByUsernamePassword acquires a security token from the authority, via Username/Password Authentication.
// NOTE: this flow is NOT recommended.
//
// Options: [WithClaims], [WithClaimsFromClient], [WithTenantID]
func (cca Client) AcquireTokenByUsernamePassword(ctx context.Context, scopes []string, username, password string, opts ...AcquireByUsernamePasswordOption) (AuthResult, error) {
	o := acquireTokenByUsernamePasswordOptions{}
	if err := options.ApplyOptions(&o, opts); err != nil {
		return AuthResult{}, err
	}
	authParams, err := cca.base.AuthParams.WithTenant(o.tenantID)
	if err != nil {
		return AuthResult{}, err
	}
	authParams.Scopes = scopes
	authParams.AuthorizationType = authority.ATUsernamePassword
	authParams.Claims = o.claims
	authParams.ClientClaims = o.clientClaims
	authParams.Username = username
	authParams.Password = password
	if o.cacheKeyComponents != nil {
		authParams.CacheKeyComponents = o.cacheKeyComponents
	}
	if o.authnScheme != nil {
		authParams.AuthnScheme = o.authnScheme
	}

	token, err := cca.base.Token.UsernamePassword(ctx, authParams)
	if err != nil {
		return AuthResult{}, err
	}
	return cca.base.AuthResultFromToken(ctx, authParams, token)
}

// acquireTokenByAuthCodeOptions contains the optional parameters used to acquire an access token using the authorization code flow.
type acquireTokenByAuthCodeOptions struct {
	challenge, claims, tenantID string
	clientClaims                string
	cacheKeyComponents          map[string]string
}

// AcquireByAuthCodeOption is implemented by options for AcquireTokenByAuthCode
type AcquireByAuthCodeOption interface {
	acquireByAuthCodeOption()
}

// WithChallenge allows you to provide a challenge for the .AcquireTokenByAuthCode() call.
func WithChallenge(challenge string) interface {
	AcquireByAuthCodeOption
	options.CallOption
} {
	return struct {
		AcquireByAuthCodeOption
		options.CallOption
	}{
		CallOption: options.NewCallOption(
			func(a any) error {
				switch t := a.(type) {
				case *acquireTokenByAuthCodeOptions:
					t.challenge = challenge
				default:
					return fmt.Errorf("unexpected options type %T", a)
				}
				return nil
			},
		),
	}
}

// AcquireTokenByAuthCode is a request to acquire a security token from the authority, using an authorization code.
// The specified redirect URI must be the same URI that was used when the authorization code was requested.
//
// Options: [WithChallenge], [WithClaims], [WithClaimsFromClient], [WithTenantID]
func (cca Client) AcquireTokenByAuthCode(ctx context.Context, code string, redirectURI string, scopes []string, opts ...AcquireByAuthCodeOption) (AuthResult, error) {
	o := acquireTokenByAuthCodeOptions{}
	if err := options.ApplyOptions(&o, opts); err != nil {
		return AuthResult{}, err
	}

	params := base.AcquireTokenAuthCodeParameters{
		Scopes:             scopes,
		Code:               code,
		Challenge:          o.challenge,
		Claims:             o.claims,
		ClientClaims:       o.clientClaims,
		AppType:            accesstokens.ATConfidential,
		Credential:         cca.cred, // This setting differs from public.Client.AcquireTokenByAuthCode
		RedirectURI:        redirectURI,
		TenantID:           o.tenantID,
		CacheKeyComponents: o.cacheKeyComponents,
	}

	return cca.base.AcquireTokenByAuthCode(ctx, params)
}

// acquireTokenByCredentialOptions contains optional configuration for AcquireTokenByCredential
type acquireTokenByCredentialOptions struct {
	claims, tenantID    string
	clientClaims        string
	authnScheme         AuthenticationScheme
	extraBodyParameters map[string]string
	cacheKeyComponents  map[string]string
	isMtlsPoP           bool
}

// AcquireByCredentialOption is implemented by options for AcquireTokenByCredential
type AcquireByCredentialOption interface {
	acquireByCredOption()
}

// AcquireTokenByCredential acquires a security token from the authority, using the client credentials grant.
//
// Options: [WithClaims], [WithClaimsFromClient], [WithTenantID], [WithFMIPath], [WithAttribute], [WithMtlsProofOfPossession]
func (cca Client) AcquireTokenByCredential(ctx context.Context, scopes []string, opts ...AcquireByCredentialOption) (AuthResult, error) {
	o := acquireTokenByCredentialOptions{}
	err := options.ApplyOptions(&o, opts)
	if err != nil {
		return AuthResult{}, err
	}
	authParams, err := cca.base.AuthParams.WithTenant(o.tenantID)
	if err != nil {
		return AuthResult{}, err
	}
	authParams.Scopes = scopes
	authParams.AuthorizationType = authority.ATClientCredentials
	authParams.Claims = o.claims
	authParams.ClientClaims = o.clientClaims
	authnScheme := o.authnScheme
	var mtlsBindingCert *tls.Certificate
	if o.isMtlsPoP {
		// Refuse the combination rather than silently discarding the caller's scheme. This is
		// checked first because it depends on nothing but the options that were passed, so the
		// caller gets told exactly which call is wrong.
		if authnScheme != nil {
			return AuthResult{}, errMtlsPoPWithAuthnScheme
		}
		// The credential is resolved before the authority is validated, on purpose: a credential
		// that can't produce a binding certificate must report that, not an authority error, so the
		// missing-certificate contract survives regardless of how the authority is configured. MSAL
		// .NET orders these the same way in MtlsPopParametersInitializer, where
		// ValidateAadAuthorityForPop runs after the credential provider.
		if err := validateMtlsCredential(cca.cred); err != nil {
			return AuthResult{}, err
		}
		mtlsBindingCert, err = cca.resolveMtlsBindingCert()
		if err != nil {
			return AuthResult{}, err
		}
		// Validate the authority here rather than leaving it to the token request. It used to be
		// enforced only while deriving the mTLS endpoint, so an unsupported authority survived
		// credential resolution, the silent cache lookup and endpoint discovery before being
		// rejected on the network. MSAL .NET validates during parameter initialization, before any
		// cache or discovery work. The check still runs on the network path too, so it can't be
		// bypassed by another entry point.
		if err := authParams.AuthorityInfo.ValidateMtlsPoP(); err != nil {
			return AuthResult{}, err
		}
		authnScheme = authority.NewMtlsPoPAuthenticationScheme(mtlsBindingCert.Leaf)
		authParams.IsMtlsPoP = true
		authParams.MtlsBindingCert = mtlsBindingCert
	}
	if authnScheme != nil {
		authParams.AuthnScheme = authnScheme
	}
	authParams.ExtraBodyParameters = o.extraBodyParameters
	authParams.CacheKeyComponents = o.cacheKeyComponents
	if o.claims == "" {
		silentParameters := base.AcquireTokenSilentParameters{
			Scopes:              scopes,
			Account:             Account{}, // empty account for app token
			RequestType:         accesstokens.ATConfidential,
			Credential:          cca.cred,
			IsAppCache:          true,
			TenantID:            o.tenantID,
			AuthnScheme:         authnScheme,
			Claims:              o.claims,
			ClientClaims:        o.clientClaims,
			ExtraBodyParameters: o.extraBodyParameters,
			CacheKeyComponents:  o.cacheKeyComponents,
			IsMtlsPoP:           o.isMtlsPoP,
			MtlsBindingCert:     mtlsBindingCert,
		}

		// Use internal method with empty account (service principal scenario)
		cache, err := cca.acquireTokenSilentInternal(ctx, silentParameters)
		if err == nil {
			return cache, nil
		}
	}

	token, err := cca.base.Token.Credential(ctx, authParams, cca.cred)
	if err != nil {
		return AuthResult{}, err
	}
	return cca.base.AuthResultFromToken(ctx, authParams, token)
}

// acquireTokenOnBehalfOfOptions contains optional configuration for AcquireTokenOnBehalfOf
type acquireTokenOnBehalfOfOptions struct {
	claims, tenantID   string
	clientClaims       string
	cacheKeyComponents map[string]string
}

// AcquireOnBehalfOfOption is implemented by options for AcquireTokenOnBehalfOf
type AcquireOnBehalfOfOption interface {
	acquireOBOOption()
}

// AcquireTokenOnBehalfOf acquires a security token for an app using middle tier apps access token.
// Refer https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow.
//
// Options: [WithClaims], [WithClaimsFromClient], [WithTenantID]
func (cca Client) AcquireTokenOnBehalfOf(ctx context.Context, userAssertion string, scopes []string, opts ...AcquireOnBehalfOfOption) (AuthResult, error) {
	o := acquireTokenOnBehalfOfOptions{}
	if err := options.ApplyOptions(&o, opts); err != nil {
		return AuthResult{}, err
	}
	params := base.AcquireTokenOnBehalfOfParameters{
		Scopes:             scopes,
		UserAssertion:      userAssertion,
		Claims:             o.claims,
		ClientClaims:       o.clientClaims,
		Credential:         cca.cred,
		TenantID:           o.tenantID,
		CacheKeyComponents: o.cacheKeyComponents,
	}
	return cca.base.AcquireTokenOnBehalfOf(ctx, params)
}

// Account gets the account in the token cache with the specified homeAccountID.
func (cca Client) Account(ctx context.Context, accountID string) (Account, error) {
	return cca.base.Account(ctx, accountID)
}

// RemoveAccount signs the account out and forgets account from token cache.
func (cca Client) RemoveAccount(ctx context.Context, account Account) error {
	return cca.base.RemoveAccount(ctx, account)
}

// WithFMIPath specifies the path to a federated managed identity.
// The path should point to a valid FMI configuration file that contains the necessary
// identity information for authentication.
func WithFMIPath(path string) interface {
	AcquireByCredentialOption
	options.CallOption
} {
	return struct {
		AcquireByCredentialOption
		options.CallOption
	}{
		CallOption: options.NewCallOption(
			func(a any) error {
				switch t := a.(type) {
				case *acquireTokenByCredentialOptions:
					if t.extraBodyParameters == nil {
						t.extraBodyParameters = make(map[string]string)
					}
					if t.cacheKeyComponents == nil {
						t.cacheKeyComponents = make(map[string]string)
					}
					t.cacheKeyComponents["fmi_path"] = path
					t.extraBodyParameters["fmi_path"] = path
				default:
					return fmt.Errorf("unexpected options type %T", a)
				}
				return nil
			},
		),
	}
}

// WithAttribute specifies an identity attribute to include in the token request.
// The attribute is sent as "attributes" in the request body and returned as "xmc_attr"
// in the access token claims. This is sometimes used withFMIPath
func WithAttribute(attrValue string) interface {
	AcquireByCredentialOption
	options.CallOption
} {
	return struct {
		AcquireByCredentialOption
		options.CallOption
	}{
		CallOption: options.NewCallOption(
			func(a any) error {
				switch t := a.(type) {
				case *acquireTokenByCredentialOptions:
					if t.extraBodyParameters == nil {
						t.extraBodyParameters = make(map[string]string)
					}
					t.extraBodyParameters["attributes"] = attrValue
				default:
					return fmt.Errorf("unexpected options type %T", a)
				}
				return nil
			},
		),
	}
}

// WithMtlsProofOfPossession requests an mTLS-bound proof-of-possession token (token_type=mtls_pop):
// the binding certificate is presented as the client certificate in the mutual-TLS handshake to the
// token endpoint (rewritten from login.* to mtlsauth.*) and the returned token is bound to that
// certificate. The authority must be tenanted (not /common, /organizations, or /consumers) and in a
// supported cloud.
//
// The binding certificate is inferred from a [NewCredFromCert] or [NewCredFromTLSCertificate]
// credential. The result exposes it via [AuthResult.BindingCertificate] — a *tls.Certificate
// carrying the parsed leaf and the private key, ready to drop into tls.Config.Certificates — and
// its thumbprint via [AuthResult.BindingCertificateThumbprint].
//
// mTLS PoP is app-only: it is available on [Client.AcquireTokenByCredential] (the client credentials
// flow) only, because the binding certificate authenticates the application, not a user, so a
// user-delegated token can never be bound to it. This matches MSAL .NET, where the option exists only
// on AcquireTokenForClient.
//
// A non-exportable key (KeyGuard/CNG/HSM) works here without signing anything at the application
// layer, because the key is used solely for the TLS handshake. Such a key can also sign client
// assertions for the other flows; see [NewCredFromTLSCertificate].
//
// The credential and the authority are both validated up front, before any cache lookup or network
// call. A credential that cannot present a client certificate is reported first, so that error is
// what a caller sees even when the authority is also unsupported.
//
// This option cannot be combined with [WithAuthenticationScheme]; supplying both returns an error.
// mTLS PoP installs its own authentication scheme, so accepting both would mean silently discarding
// the caller's scheme along with its request parameters, cache key contribution and result
// formatting. This deliberately diverges from MSAL .NET, which composes with schemes that implement
// its IAuthenticationOperation3 capability interface and silently replaces the scheme otherwise. Go
// has no equivalent capability interface and no composable scheme to compose with — the only
// AccessTokenType implementations are the bearer scheme, the mTLS PoP scheme itself and a test mock
// — so a loud failure is more useful than a silent one.
func WithMtlsProofOfPossession() interface {
	AcquireByCredentialOption
	options.CallOption
} {
	return struct {
		AcquireByCredentialOption
		options.CallOption
	}{
		CallOption: options.NewCallOption(
			func(a any) error {
				switch t := a.(type) {
				case *acquireTokenByCredentialOptions:
					t.isMtlsPoP = true
				default:
					return fmt.Errorf("unexpected options type %T", a)
				}
				return nil
			},
		),
	}
}

// resolveMtlsBindingCert returns the binding certificate for an mTLS PoP request, derived from a
// certificate credential (NewCredFromCert or NewCredFromTLSCertificate). The credential's key is
// carried through unchanged, so a crypto.Signer backed by a non-exportable key reaches the TLS
// handshake intact.
func (cca Client) resolveMtlsBindingCert() (*tls.Certificate, error) {
	if cca.cred != nil && cca.cred.Cert != nil && cca.cred.Key != nil {
		der := make([][]byte, 0, len(cca.cred.X5c))
		for _, b64 := range cca.cred.X5c {
			d, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return nil, fmt.Errorf("invalid x5c certificate entry: %w", err)
			}
			der = append(der, d)
		}
		if len(der) == 0 {
			der = [][]byte{cca.cred.Cert.Raw}
		}
		return &tls.Certificate{Certificate: der, PrivateKey: cca.cred.Key, Leaf: cca.cred.Cert}, nil
	}
	return nil, errors.New("mTLS proof-of-possession requires a certificate credential (NewCredFromCert or NewCredFromTLSCertificate)")
}

// errMtlsPoPWithAuthnScheme is returned when a caller combines WithAuthenticationScheme with
// WithMtlsProofOfPossession. See the WithMtlsProofOfPossession doc comment for why this is an error
// in Go where MSAL .NET silently replaces the scheme.
var errMtlsPoPWithAuthnScheme = errors.New(
	"WithAuthenticationScheme and WithMtlsProofOfPossession cannot be combined: " +
		"mTLS proof-of-possession installs its own authentication scheme, which would discard the one " +
		"passed to WithAuthenticationScheme along with its request parameters, cache key contribution " +
		"and result formatting; pass only one of the two",
)

// validateMtlsCredential rejects credential kinds that can't perform mTLS proof-of-possession.
func validateMtlsCredential(cred *accesstokens.Credential) error {
	if cred == nil {
		return errors.New("mTLS proof-of-possession requires a certificate credential (NewCredFromCert or NewCredFromTLSCertificate)")
	}
	if cred.Secret != "" {
		return errors.New("mTLS proof-of-possession is not supported with a client secret credential")
	}
	if cred.TokenProvider != nil {
		return errors.New("mTLS proof-of-possession is not supported with a token-provider credential")
	}
	if cred.AssertionCallback != nil {
		return errors.New("mTLS proof-of-possession is not supported with an assertion credential")
	}
	return nil
}

// AcquireByUserFICOption is implemented by options for AcquireTokenByUserFederatedIdentityCredential.
type AcquireByUserFICOption interface {
	acquireByUserFICOption()
}

// acquireTokenByUserFICOptions contains optional configuration for AcquireTokenByUserFederatedIdentityCredential.
type acquireTokenByUserFICOptions struct {
	claims, tenantID   string
	clientClaims       string
	username           string
	userObjectID       string
	cacheKeyComponents map[string]string
}

// acquireByUserFICOption is a marker method that restricts option types to the user_fic API.
func (acquireTokenByUserFICOptions) acquireByUserFICOption() {}

// WithUserObjectID specifies the target user by their object ID (OID) for the user_fic flow.
// This is mutually exclusive with WithUserFICUsername.
func WithUserObjectID(oid string) interface {
	AcquireByUserFICOption
	options.CallOption
} {
	return struct {
		AcquireByUserFICOption
		options.CallOption
	}{
		CallOption: options.NewCallOption(
			func(a any) error {
				switch t := a.(type) {
				case *acquireTokenByUserFICOptions:
					t.userObjectID = oid
				default:
					return fmt.Errorf("unexpected options type %T", a)
				}
				return nil
			},
		),
	}
}

// WithUserFICUsername specifies the target user by their UPN (username) for the user_fic flow.
// This is mutually exclusive with WithUserObjectID.
func WithUserFICUsername(username string) interface {
	AcquireByUserFICOption
	options.CallOption
} {
	return struct {
		AcquireByUserFICOption
		options.CallOption
	}{
		CallOption: options.NewCallOption(
			func(a any) error {
				switch t := a.(type) {
				case *acquireTokenByUserFICOptions:
					t.username = username
				default:
					return fmt.Errorf("unexpected options type %T", a)
				}
				return nil
			},
		),
	}
}

// AcquireTokenByUserFederatedIdentityCredential acquires a user-scoped token using the user_fic grant type.
// This exchanges a federated identity credential (assertion) for a user token, enabling an agent
// to act on behalf of a user. The result includes an Account that can be used with
// [Client.AcquireTokenSilent] for subsequent cached access.
//
// Parameters:
//   - ctx: Context for the request.
//   - scopes: Scopes requested for the token.
//   - assertion: The federated identity credential (instance token) to exchange.
//   - opts: Options including user identification (exactly one of WithUserObjectID or WithUserFICUsername
//     is required), [WithClaims], [WithClaimsFromClient], [WithTenantID].
//
// Options: [WithUserObjectID], [WithUserFICUsername], [WithClaims], [WithClaimsFromClient], [WithTenantID]
func (cca Client) AcquireTokenByUserFederatedIdentityCredential(ctx context.Context, scopes []string, assertion string, opts ...AcquireByUserFICOption) (AuthResult, error) {
	o := acquireTokenByUserFICOptions{}
	if err := options.ApplyOptions(&o, opts); err != nil {
		return AuthResult{}, err
	}

	if assertion == "" {
		return AuthResult{}, errors.New("assertion must not be empty")
	}
	if o.username == "" && o.userObjectID == "" {
		return AuthResult{}, errors.New("exactly one of WithUserObjectID or WithUserFICUsername must be specified")
	}
	if o.username != "" && o.userObjectID != "" {
		return AuthResult{}, errors.New("WithUserObjectID and WithUserFICUsername are mutually exclusive")
	}

	params := base.AcquireTokenByUserFICParameters{
		Scopes:                          scopes,
		Claims:                          o.claims,
		ClientClaims:                    o.clientClaims,
		Credential:                      cca.cred,
		TenantID:                        o.tenantID,
		UserFederatedIdentityCredential: assertion,
		Username:                        o.username,
		UserObjectID:                    o.userObjectID,
		CacheKeyComponents:              o.cacheKeyComponents,
	}
	return cca.base.AcquireTokenByUserFIC(ctx, params)
}
