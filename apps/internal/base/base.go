// Package base contains a "Base" client that is used by the external public.Client and confidential.Client.
// Base holds shared attributes that must be available to both clients and methods that act as
// shared calls.
package base

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/storage"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
)

const (
	// AuthorityPublicCloud is the default AAD authority host
	AuthorityPublicCloud = "https://login.microsoftonline.com/common"
	scopeSeparator       = " "
)

// manager provides an internal cache. It is defined to allow faking the cache in tests.
// In production it's a *storage.Manager or *storage.PartitionedManager.
type manager interface {
	cache.Serializer
	Read(context.Context, authority.AuthParams) (storage.TokenResponse, error)
	Write(authority.AuthParams, accesstokens.TokenResponse) (shared.Account, error)
}

// accountManager is a manager that also caches accounts. In production it's a *storage.Manager.
type accountManager interface {
	manager
	AllAccounts() []shared.Account
	Account(homeAccountID string) shared.Account
	RemoveAccount(account shared.Account, clientID string)
}

// AcquireTokenSilentParameters contains the parameters to acquire a token silently (from cache).
type AcquireTokenSilentParameters struct {
	Scopes              []string
	Account             shared.Account
	RequestType         accesstokens.AppType
	Credential          *accesstokens.Credential
	IsAppCache          bool
	TenantID            string
	UserAssertion       string
	AuthorizationType   authority.AuthorizeType
	Claims              string
	ClientClaims        string
	AuthnScheme         authority.AuthenticationScheme
	ExtraBodyParameters map[string]string
	CacheKeyComponents  map[string]string
	// IsMtlsPoP requests an mTLS-bound proof-of-possession token (token_type=mtls_pop).
	IsMtlsPoP bool
	// MtlsBindingCert is the certificate presented on the mutual-TLS handshake when IsMtlsPoP or
	// MtlsTransport is set.
	MtlsBindingCert *tls.Certificate
	// MtlsTransport requests Bearer-over-mTLS: route over the mutual-TLS transport (mtlsauth.*) using
	// MtlsBindingCert but return a plain Bearer token (see authority.AuthParams.MtlsTransport).
	MtlsTransport bool
}

// AcquireTokenAuthCodeParameters contains the parameters required to acquire an access token using the auth code flow.
// To use PKCE, set the CodeChallengeParameter.
// Code challenges are used to secure authorization code grants; for more information, visit
// https://tools.ietf.org/html/rfc7636.
type AcquireTokenAuthCodeParameters struct {
	Scopes             []string
	Code               string
	Challenge          string
	Claims             string
	ClientClaims       string
	RedirectURI        string
	AppType            accesstokens.AppType
	Credential         *accesstokens.Credential
	TenantID           string
	CacheKeyComponents map[string]string
	// MtlsBindingCert / MtlsTransport request Bearer-over-mTLS for the auth-code flow (route over
	// mtlsauth.* with the certificate on the handshake, return a plain Bearer token).
	MtlsBindingCert *tls.Certificate
	MtlsTransport   bool
}

type AcquireTokenOnBehalfOfParameters struct {
	Scopes             []string
	Claims             string
	ClientClaims       string
	Credential         *accesstokens.Credential
	TenantID           string
	UserAssertion      string
	CacheKeyComponents map[string]string
	// MtlsBindingCert / MtlsTransport request Bearer-over-mTLS for the on-behalf-of flow (route over
	// mtlsauth.* with the certificate on the handshake, return a plain Bearer token).
	MtlsBindingCert *tls.Certificate
	MtlsTransport   bool
}

// AcquireTokenByUserFICParameters contains the parameters to acquire a user token via the user_fic flow.
type AcquireTokenByUserFICParameters struct {
	Scopes                          []string
	Claims                          string
	ClientClaims                    string
	Credential                      *accesstokens.Credential
	TenantID                        string
	UserFederatedIdentityCredential string
	Username                        string
	UserObjectID                    string
	CacheKeyComponents              map[string]string
}

// AuthResult contains the results of one token acquisition operation in PublicClientApplication
// or ConfidentialClientApplication. For details see https://aka.ms/msal-net-authenticationresult
type AuthResult struct {
	Account        shared.Account
	IDToken        accesstokens.IDToken
	AccessToken    string
	ExpiresOn      time.Time
	GrantedScopes  []string
	DeclinedScopes []string
	Metadata       AuthResultMetadata
	// BindingCertificate is the certificate bound to an mTLS proof-of-possession token
	// (Metadata.TokenType == "mtls_pop"); it is nil for Bearer tokens. Leaf is always populated with
	// the parsed public leaf certificate. PrivateKey is the key MSAL used for the token request; it
	// only has to implement crypto.Signer, so besides an exportable *rsa.PrivateKey it may be a
	// non-exportable key backed by KeyGuard, CNG or an HSM, and callers must not assume the key
	// material can be exported. Its concrete type is not part of the contract and will not
	// necessarily be the key MSAL obtained from the platform: MSAL wraps it so the underlying
	// handle stays open for as long as any copy of this certificate is reachable. Use it through
	// crypto.Signer and do not type-assert it to a concrete type.
	//
	// The certificate may be copied by value; every copy shares the one key and stays valid.
	//
	// Present it as the client certificate when calling the resource, or the resource rejects the
	// bound token. Two properties of Go's TLS stack make that harder than assigning it to
	// tls.Config.Certificates, and neither one fails in a way that names the real cause:
	//
	//   - Certificates is filtered against the certificate authorities the server advertises, and
	//     Go silently sends nothing when none match. A binding certificate is issued by an internal
	//     CA the resource need not advertise, so supply it from GetClientCertificate instead, which
	//     is not filtered.
	//   - A resource may not ask for the certificate during the handshake at all. Azure Key Vault
	//     completes the handshake, reads the request, sees the mtls_pop scheme, and only then asks
	//     by renegotiating. Go declines renegotiation by default and does not implement the TLS 1.3
	//     equivalent, post-handshake authentication, so the connection is torn down and the caller
	//     sees a bare connection reset. Set MaxVersion to tls.VersionTLS12 and Renegotiation to
	//     tls.RenegotiateOnceAsClient to answer it.
	//
	// It is excluded from JSON: encoding/json walks into an *rsa.PrivateKey's exported fields, so
	// marshalling an AuthResult would otherwise emit the private exponent and primes into whatever
	// consumes the output (a log, a trace, a cache file).
	BindingCertificate *tls.Certificate `json:"-"`
}

// AuthResultMetadata which contains meta data for the AuthResult
type AuthResultMetadata struct {
	RefreshOn   time.Time
	TokenSource TokenSource
	// TokenType is the token_type of the access token, for example "Bearer" or "mtls_pop".
	TokenType string
}

// BindingCertificateThumbprint returns the base64url-encoded SHA-256 thumbprint (x5t#S256) of the
// binding certificate, or "" when there is no binding certificate.
func (ar AuthResult) BindingCertificateThumbprint() string {
	if ar.BindingCertificate == nil || ar.BindingCertificate.Leaf == nil {
		return ""
	}
	sum := sha256.Sum256(ar.BindingCertificate.Leaf.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// bindingCertWithLeaf returns a binding certificate whose Leaf is guaranteed to be populated, or nil
// when cert is nil, carries no DER chain, or carries no parsable leaf. It never writes to cert: the
// same *tls.Certificate is retained by the per-thumbprint mTLS client cache, so populating Leaf in
// place would race with concurrent token acquisitions.
//
// The DER chain is deep-copied for the same reason. A shallow copy would share the backing arrays of
// Certificate with the cached certificate, so a caller mutating
// result.BindingCertificate.Certificate[i] could corrupt a future TLS handshake or race an in-flight
// one.
//
// The leaf is re-parsed from that copy rather than reused, which is why the copy is made first.
// x509.ParseCertificate aliases the DER it is handed instead of copying it, so a parsed certificate's
// Raw (and RawTBSCertificate, RawSubject, ...) stays a live window onto whichever chain it came from.
// Reusing cert.Leaf would therefore hand back the credential's own *x509.Certificate: mutating the
// returned Leaf.Raw would change every later thumbprint and authentication-scheme key ID, race
// concurrent acquisitions, and leave Leaf disagreeing with the Certificate bytes actually presented on
// the wire. Parsing from out.Certificate[0] keeps Leaf.Raw pointing into this result's private copy,
// so Leaf and Certificate always describe the same bytes and a caller can only corrupt its own value.
//
// PrivateKey is deliberately shared rather than copied: callers need the live signer to present the
// certificate on the handshake to the resource, and a non-exportable key cannot be copied at all.
func bindingCertWithLeaf(cert *tls.Certificate) *tls.Certificate {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil
	}
	out := *cert
	out.Certificate = copyDERChain(cert.Certificate)
	leaf, err := x509.ParseCertificate(out.Certificate[0])
	if err != nil {
		return nil
	}
	out.Leaf = leaf
	return &out
}

// copyDERChain deep-copies a DER chain so the returned certificate shares no backing array with the
// cached *tls.Certificate it was derived from.
func copyDERChain(chain [][]byte) [][]byte {
	if chain == nil {
		return nil
	}
	out := make([][]byte, len(chain))
	for i, der := range chain {
		if der == nil {
			continue
		}
		cp := make([]byte, len(der))
		copy(cp, der)
		out[i] = cp
	}
	return out
}

type TokenSource int

// These are all the types of token flows.
const (
	TokenSourceIdentityProvider TokenSource = 0
	TokenSourceCache            TokenSource = 1
)

// AuthResultFromStorage creates an AuthResult from a storage token response (which is generated from the cache).
func AuthResultFromStorage(storageTokenResponse storage.TokenResponse) (AuthResult, error) {
	if err := storageTokenResponse.AccessToken.Validate(); err != nil {
		return AuthResult{}, fmt.Errorf("problem with access token in StorageTokenResponse: %w", err)
	}
	account := storageTokenResponse.Account
	accessToken := storageTokenResponse.AccessToken.Secret
	grantedScopes := strings.Split(storageTokenResponse.AccessToken.Scopes, scopeSeparator)

	// Checking if there was an ID token in the cache; this will throw an error in the case of confidential client applications.
	var idToken accesstokens.IDToken
	if !storageTokenResponse.IDToken.IsZero() {
		err := idToken.UnmarshalJSON([]byte(storageTokenResponse.IDToken.Secret))
		if err != nil {
			return AuthResult{}, fmt.Errorf("problem decoding JWT token: %w", err)
		}
	}
	return AuthResult{
		Account:        account,
		IDToken:        idToken,
		AccessToken:    accessToken,
		ExpiresOn:      storageTokenResponse.AccessToken.ExpiresOn.T,
		GrantedScopes:  grantedScopes,
		DeclinedScopes: nil,
		Metadata: AuthResultMetadata{
			TokenSource: TokenSourceCache,
			RefreshOn:   storageTokenResponse.AccessToken.RefreshOn.T,
			TokenType:   storageTokenResponse.AccessToken.TokenType,
		},
	}, nil
}

// NewAuthResult creates an AuthResult.
func NewAuthResult(tokenResponse accesstokens.TokenResponse, account shared.Account) (AuthResult, error) {
	if len(tokenResponse.DeclinedScopes) > 0 {
		return AuthResult{}, fmt.Errorf("token response failed because declined scopes are present: %s", strings.Join(tokenResponse.DeclinedScopes, ","))
	}
	return AuthResult{
		Account:       account,
		IDToken:       tokenResponse.IDToken,
		AccessToken:   tokenResponse.AccessToken,
		ExpiresOn:     tokenResponse.ExpiresOn,
		GrantedScopes: tokenResponse.GrantedScopes.Slice,
		Metadata: AuthResultMetadata{
			TokenSource: TokenSourceIdentityProvider,
			RefreshOn:   tokenResponse.RefreshOn.T,
			TokenType:   tokenResponse.TokenType,
		},
	}, nil
}

// Client is a base client that provides access to common methods and primatives that
// can be used by multiple clients.
type Client struct {
	Token   *oauth.Client
	manager accountManager // *storage.Manager or fakeManager in tests
	// pmanager is a partitioned cache for OBO authentication. *storage.PartitionedManager or fakeManager in tests
	pmanager manager

	AuthParams      authority.AuthParams // DO NOT EVER MAKE THIS A POINTER! See "Note" in New().
	cacheAccessor   cache.ExportReplace
	cacheAccessorMu *sync.RWMutex
	canRefresh      map[string]*atomic.Value
	canRefreshMu    *sync.Mutex
}

// Option is an optional argument to the New constructor.
type Option func(c *Client) error

// WithCacheAccessor allows you to set some type of cache for storing authentication tokens.
func WithCacheAccessor(ca cache.ExportReplace) Option {
	return func(c *Client) error {
		if ca != nil {
			c.cacheAccessor = ca
		}
		return nil
	}
}

// WithClientCapabilities allows configuring one or more client capabilities such as "CP1"
func WithClientCapabilities(capabilities []string) Option {
	return func(c *Client) error {
		var err error
		if len(capabilities) > 0 {
			cc, err := authority.NewClientCapabilities(capabilities)
			if err == nil {
				c.AuthParams.Capabilities = cc
			}
		}
		return err
	}
}

// WithKnownAuthorityHosts specifies hosts Client shouldn't validate or request metadata for because they're known to the user
func WithKnownAuthorityHosts(hosts []string) Option {
	return func(c *Client) error {
		cp := make([]string, len(hosts))
		copy(cp, hosts)
		c.AuthParams.KnownAuthorityHosts = cp
		return nil
	}
}

// WithX5C specifies if x5c claim(public key of the certificate) should be sent to STS to enable Subject Name Issuer Authentication.
func WithX5C(sendX5C bool) Option {
	return func(c *Client) error {
		c.AuthParams.SendX5C = sendX5C
		return nil
	}
}

func WithRegionDetection(region string) Option {
	return func(c *Client) error {
		c.AuthParams.AuthorityInfo.Region = region
		return nil
	}
}

func WithInstanceDiscovery(instanceDiscoveryEnabled bool) Option {
	return func(c *Client) error {
		c.AuthParams.AuthorityInfo.ValidateAuthority = instanceDiscoveryEnabled
		c.AuthParams.AuthorityInfo.InstanceDiscoveryDisabled = !instanceDiscoveryEnabled
		return nil
	}
}

// New is the constructor for Base.
func New(clientID string, authorityURI string, token *oauth.Client, options ...Option) (Client, error) {
	//By default, validateAuthority is set to true and instanceDiscoveryDisabled is set to false
	authInfo, err := authority.NewInfoFromAuthorityURI(authorityURI, true, false)
	if err != nil {
		return Client{}, err
	}
	authParams := authority.NewAuthParams(clientID, authInfo)
	client := Client{ // Note: Hey, don't even THINK about making Base into *Base. See "design notes" in public.go and confidential.go
		Token:           token,
		AuthParams:      authParams,
		cacheAccessorMu: &sync.RWMutex{},
		manager:         storage.New(token),
		pmanager:        storage.NewPartitionedManager(token),
		canRefresh:      make(map[string]*atomic.Value),
		canRefreshMu:    &sync.Mutex{},
	}
	for _, o := range options {
		if err = o(&client); err != nil {
			break
		}
	}
	return client, err

}

// AuthCodeURL creates a URL used to acquire an authorization code.
func (b Client) AuthCodeURL(ctx context.Context, clientID, redirectURI string, scopes []string, authParams authority.AuthParams) (string, error) {
	endpoints, err := b.Token.ResolveEndpoints(ctx, authParams.AuthorityInfo, "")
	if err != nil {
		return "", err
	}

	baseURL, err := url.Parse(endpoints.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}

	claims, err := authParams.MergeCapabilitiesAndClaims()
	if err != nil {
		return "", err
	}

	v := url.Values{}
	v.Add("client_id", clientID)
	v.Add("response_type", "code")
	v.Add("redirect_uri", redirectURI)
	v.Add("scope", strings.Join(scopes, scopeSeparator))
	if authParams.State != "" {
		v.Add("state", authParams.State)
	}
	if claims != "" {
		v.Add("claims", claims)
	}
	if authParams.CodeChallenge != "" {
		v.Add("code_challenge", authParams.CodeChallenge)
	}
	if authParams.CodeChallengeMethod != "" {
		v.Add("code_challenge_method", authParams.CodeChallengeMethod)
	}
	if authParams.LoginHint != "" {
		v.Add("login_hint", authParams.LoginHint)
	}
	if authParams.Prompt != "" {
		v.Add("prompt", authParams.Prompt)
	}
	if authParams.DomainHint != "" {
		v.Add("domain_hint", authParams.DomainHint)
	}
	// Use form_post response mode for interactive auth to avoid exposing the auth code in the URL
	if authParams.AuthorizationType == authority.ATInteractive {
		v.Add("response_mode", "form_post")
	}
	baseURL.RawQuery = v.Encode()
	return baseURL.String(), nil
}

func (b Client) AcquireTokenSilent(ctx context.Context, silent AcquireTokenSilentParameters) (AuthResult, error) {
	ar := AuthResult{}
	// when tenant == "", the caller didn't specify a tenant and WithTenant will choose the client's configured tenant
	tenant := silent.TenantID
	authParams, err := b.AuthParams.WithTenant(tenant)
	if err != nil {
		return ar, err
	}
	authParams.Scopes = silent.Scopes
	authParams.HomeAccountID = silent.Account.HomeAccountID
	authParams.AuthorizationType = silent.AuthorizationType
	authParams.Claims = silent.Claims
	authParams.ClientClaims = silent.ClientClaims
	authParams.UserAssertion = silent.UserAssertion
	authParams.IsAppTokenCache = silent.IsAppCache
	if silent.AuthnScheme != nil {
		authParams.AuthnScheme = silent.AuthnScheme
	}
	if silent.CacheKeyComponents != nil {
		authParams.CacheKeyComponents = silent.CacheKeyComponents
	}
	if silent.ExtraBodyParameters != nil {
		authParams.ExtraBodyParameters = silent.ExtraBodyParameters
	}
	authParams.IsMtlsPoP = silent.IsMtlsPoP
	authParams.MtlsBindingCert = silent.MtlsBindingCert
	authParams.MtlsTransport = silent.MtlsTransport
	if silent.MtlsTransport {
		// Bearer-over-mTLS forces the x5c chain onto the private_key_jwt client assertion regardless of
		// the app-level WithX5C setting (mirrors MSAL .NET's Mode=OAuth credential resolution).
		authParams.SendX5C = true
	}
	m := b.pmanager
	if authParams.AuthorizationType != authority.ATOnBehalfOf {
		authParams.AuthorizationType = authority.ATRefreshToken
		m = b.manager
	}
	if b.cacheAccessor != nil {
		key := authParams.CacheKey(silent.IsAppCache)
		b.cacheAccessorMu.RLock()
		err = b.cacheAccessor.Replace(ctx, m, cache.ReplaceHints{PartitionKey: key})
		b.cacheAccessorMu.RUnlock()
	}
	if err != nil {
		return ar, err
	}
	storageTokenResponse, err := m.Read(ctx, authParams)
	if err != nil {
		return ar, err
	}

	// ignore cached access tokens when given claims
	if silent.Claims == "" {
		ar, err = AuthResultFromStorage(storageTokenResponse)
		if err == nil {
			if authParams.IsMtlsPoP {
				ar.BindingCertificate = bindingCertWithLeaf(authParams.MtlsBindingCert)
			}
			if rt := storageTokenResponse.AccessToken.RefreshOn.T; !rt.IsZero() && Now().After(rt) {
				b.canRefreshMu.Lock()
				refreshValue, ok := b.canRefresh[tenant]
				if !ok {
					refreshValue = &atomic.Value{}
					refreshValue.Store(false)
					b.canRefresh[tenant] = refreshValue
				}
				b.canRefreshMu.Unlock()
				if refreshValue.CompareAndSwap(false, true) {
					defer refreshValue.Store(false)
					// Added a check to see if the token is still same because there is a chance
					// that the token is already refreshed by another thread.
					// If the token is not same, we don't need to refresh it.
					// Which means it refreshed.
					if str, err := m.Read(ctx, authParams); err == nil && str.AccessToken.Secret == ar.AccessToken {
						switch silent.RequestType {
						case accesstokens.ATConfidential:
							if tr, er := b.Token.Credential(ctx, authParams, silent.Credential); er == nil {
								return b.AuthResultFromToken(ctx, authParams, tr)
							}
						case accesstokens.ATPublic:
							token, err := b.Token.Refresh(ctx, silent.RequestType, authParams, silent.Credential, storageTokenResponse.RefreshToken)
							if err != nil {
								return ar, err
							}
							return b.AuthResultFromToken(ctx, authParams, token)
						case accesstokens.ATUnknown:
							return ar, errors.New("silent request type cannot be ATUnknown")
						}
					}
				}
			}
			ar.AccessToken, err = authParams.AuthnScheme.FormatAccessToken(ar.AccessToken)
			return ar, err
		}
	}

	// redeem a cached refresh token, if available
	if reflect.ValueOf(storageTokenResponse.RefreshToken).IsZero() {
		return ar, errors.New("no token found")
	}
	var cc *accesstokens.Credential
	if silent.RequestType == accesstokens.ATConfidential {
		cc = silent.Credential
	}
	token, err := b.Token.Refresh(ctx, silent.RequestType, authParams, cc, storageTokenResponse.RefreshToken)
	if err != nil {
		return ar, err
	}
	return b.AuthResultFromToken(ctx, authParams, token)
}

func (b Client) AcquireTokenByAuthCode(ctx context.Context, authCodeParams AcquireTokenAuthCodeParameters) (AuthResult, error) {
	authParams, err := b.AuthParams.WithTenant(authCodeParams.TenantID)
	if err != nil {
		return AuthResult{}, err
	}
	authParams.Claims = authCodeParams.Claims
	authParams.ClientClaims = authCodeParams.ClientClaims
	if authCodeParams.CacheKeyComponents != nil {
		authParams.CacheKeyComponents = authCodeParams.CacheKeyComponents
	}
	authParams.Scopes = authCodeParams.Scopes
	authParams.Redirecturi = authCodeParams.RedirectURI
	authParams.AuthorizationType = authority.ATAuthCode
	authParams.MtlsBindingCert = authCodeParams.MtlsBindingCert
	authParams.MtlsTransport = authCodeParams.MtlsTransport
	if authCodeParams.MtlsTransport {
		authParams.SendX5C = true
	}

	var cc *accesstokens.Credential
	if authCodeParams.AppType == accesstokens.ATConfidential {
		cc = authCodeParams.Credential
		authParams.IsConfidentialClient = true
	}

	req, err := accesstokens.NewCodeChallengeRequest(authParams, authCodeParams.AppType, cc, authCodeParams.Code, authCodeParams.Challenge)
	if err != nil {
		return AuthResult{}, err
	}

	token, err := b.Token.AuthCode(ctx, req)
	if err != nil {
		return AuthResult{}, err
	}

	return b.AuthResultFromToken(ctx, authParams, token)
}

// AcquireTokenOnBehalfOf acquires a security token for an app using middle tier apps access token.
func (b Client) AcquireTokenOnBehalfOf(ctx context.Context, onBehalfOfParams AcquireTokenOnBehalfOfParameters) (AuthResult, error) {
	var ar AuthResult
	silentParameters := AcquireTokenSilentParameters{
		Scopes:             onBehalfOfParams.Scopes,
		RequestType:        accesstokens.ATConfidential,
		Credential:         onBehalfOfParams.Credential,
		UserAssertion:      onBehalfOfParams.UserAssertion,
		AuthorizationType:  authority.ATOnBehalfOf,
		TenantID:           onBehalfOfParams.TenantID,
		Claims:             onBehalfOfParams.Claims,
		ClientClaims:       onBehalfOfParams.ClientClaims,
		CacheKeyComponents: onBehalfOfParams.CacheKeyComponents,
		MtlsBindingCert:    onBehalfOfParams.MtlsBindingCert,
		MtlsTransport:      onBehalfOfParams.MtlsTransport,
	}
	ar, err := b.AcquireTokenSilent(ctx, silentParameters)
	if err == nil {
		return ar, err
	}
	authParams, err := b.AuthParams.WithTenant(onBehalfOfParams.TenantID)
	if err != nil {
		return AuthResult{}, err
	}
	authParams.AuthorizationType = authority.ATOnBehalfOf
	authParams.Claims = onBehalfOfParams.Claims
	authParams.ClientClaims = onBehalfOfParams.ClientClaims
	authParams.Scopes = onBehalfOfParams.Scopes
	authParams.UserAssertion = onBehalfOfParams.UserAssertion
	if onBehalfOfParams.CacheKeyComponents != nil {
		authParams.CacheKeyComponents = onBehalfOfParams.CacheKeyComponents
	}
	authParams.MtlsBindingCert = onBehalfOfParams.MtlsBindingCert
	authParams.MtlsTransport = onBehalfOfParams.MtlsTransport
	if onBehalfOfParams.MtlsTransport {
		authParams.SendX5C = true
	}
	if authParams.ExtraBodyParameters != nil {
		authParams.ExtraBodyParameters = silentParameters.ExtraBodyParameters
	}
	token, err := b.Token.OnBehalfOf(ctx, authParams, onBehalfOfParams.Credential)
	if err == nil {
		ar, err = b.AuthResultFromToken(ctx, authParams, token)
	}
	return ar, err
}

// AcquireTokenByUserFIC acquires a user-scoped token using the user_fic grant type.
func (b Client) AcquireTokenByUserFIC(ctx context.Context, params AcquireTokenByUserFICParameters) (AuthResult, error) {
	authParams, err := b.AuthParams.WithTenant(params.TenantID)
	if err != nil {
		return AuthResult{}, err
	}
	authParams.AuthorizationType = authority.ATUserFIC
	authParams.Claims = params.Claims
	authParams.ClientClaims = params.ClientClaims
	if params.CacheKeyComponents != nil {
		authParams.CacheKeyComponents = params.CacheKeyComponents
	}
	authParams.Scopes = params.Scopes
	authParams.UserFederatedIdentityCredential = params.UserFederatedIdentityCredential
	authParams.Username = params.Username
	authParams.UserObjectID = params.UserObjectID

	token, err := b.Token.UserFederatedIdentityCredential(ctx, authParams, params.Credential)
	if err != nil {
		return AuthResult{}, err
	}
	return b.AuthResultFromToken(ctx, authParams, token)
}

func (b Client) AuthResultFromToken(ctx context.Context, authParams authority.AuthParams, token accesstokens.TokenResponse) (AuthResult, error) {
	var m manager = b.manager
	if authParams.AuthorizationType == authority.ATOnBehalfOf {
		m = b.pmanager
	}
	key := token.CacheKey(authParams)
	if b.cacheAccessor != nil {
		b.cacheAccessorMu.Lock()
		defer b.cacheAccessorMu.Unlock()
		err := b.cacheAccessor.Replace(ctx, m, cache.ReplaceHints{PartitionKey: key})
		if err != nil {
			return AuthResult{}, err
		}
	}
	account, err := m.Write(authParams, token)
	if err != nil {
		return AuthResult{}, err
	}
	ar, err := NewAuthResult(token, account)
	if err == nil && b.cacheAccessor != nil {
		err = b.cacheAccessor.Export(ctx, b.manager, cache.ExportHints{PartitionKey: key})
	}
	if err != nil {
		return AuthResult{}, err
	}

	if authParams.IsMtlsPoP {
		ar.BindingCertificate = bindingCertWithLeaf(authParams.MtlsBindingCert)
	}
	ar.AccessToken, err = authParams.AuthnScheme.FormatAccessToken(ar.AccessToken)
	return ar, err
}

// This function wraps time.Now() and is used for refreshing the application
// was created to test the function against refreshin
var Now = time.Now

func (b Client) AllAccounts(ctx context.Context) ([]shared.Account, error) {
	if b.cacheAccessor != nil {
		b.cacheAccessorMu.RLock()
		defer b.cacheAccessorMu.RUnlock()
		key := b.AuthParams.CacheKey(false)
		err := b.cacheAccessor.Replace(ctx, b.manager, cache.ReplaceHints{PartitionKey: key})
		if err != nil {
			return nil, err
		}
	}
	return b.manager.AllAccounts(), nil
}

func (b Client) Account(ctx context.Context, homeAccountID string) (shared.Account, error) {
	if b.cacheAccessor != nil {
		b.cacheAccessorMu.RLock()
		defer b.cacheAccessorMu.RUnlock()
		authParams := b.AuthParams // This is a copy, as we don't have a pointer receiver and .AuthParams is not a pointer.
		authParams.AuthorizationType = authority.AccountByID
		authParams.HomeAccountID = homeAccountID
		key := authParams.CacheKey(false)
		err := b.cacheAccessor.Replace(ctx, b.manager, cache.ReplaceHints{PartitionKey: key})
		if err != nil {
			return shared.Account{}, err
		}
	}
	return b.manager.Account(homeAccountID), nil
}

// RemoveAccount removes all the ATs, RTs and IDTs from the cache associated with this account.
func (b Client) RemoveAccount(ctx context.Context, account shared.Account) error {
	if b.cacheAccessor == nil {
		b.manager.RemoveAccount(account, b.AuthParams.ClientID)
		return nil
	}
	b.cacheAccessorMu.Lock()
	defer b.cacheAccessorMu.Unlock()
	key := b.AuthParams.CacheKey(false)
	err := b.cacheAccessor.Replace(ctx, b.manager, cache.ReplaceHints{PartitionKey: key})
	if err != nil {
		return err
	}
	b.manager.RemoveAccount(account, b.AuthParams.ClientID)
	return b.cacheAccessor.Export(ctx, b.manager, cache.ExportHints{PartitionKey: key})
}
