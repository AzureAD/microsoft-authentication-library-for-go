// Package client contains a "Base" client that is used by the external public.Client and confidential.Client.
// Base holds shared attributes that must be available to both clients and methods that act as
// shared calls.
package client

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/resolvers"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/storage"
	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/cache"
)

const (
	// AuthorityPublicCloud is the default AAD authority host
	AuthorityPublicCloud = "https://login.microsoftonline.com/common"
)

// This defines shared resources for accessing remove services.
var (
	token      *requests.Token
	rest       *ops.REST
	aeResolver *resolvers.AuthorityEndpoint
)

func init() {
	rest = ops.New()
	aeResolver = resolvers.New(rest)
	token = requests.NewToken(aeResolver)
}

// manager provides an internal cache. It is defined to allow faking the cache in tests.
// In all production use it is a *storage.Manager.
type manager interface {
	Read(ctx context.Context, authParameters msalbase.AuthParametersInternal) (msalbase.StorageTokenResponse, error)
	Write(authParameters msalbase.AuthParametersInternal, tokenResponse msalbase.TokenResponse) (msalbase.Account, error)
	GetAllAccounts() ([]msalbase.Account, error)
}

//AccountProvider is an interface representing an account that is returned to users.
//This can help with accessing the cache for tokens.
type AccountProvider interface {
	GetUsername() string
	GetHomeAccountID() string
	GetEnvironment() string
}

type noopCacheAccessor struct{}

func (n noopCacheAccessor) Replace(cache cache.Unmarshaler) {}
func (n noopCacheAccessor) Export(cache cache.Marshaler)    {}

// toLower makes all slice entries lowercase in-place. Returns the same slice that was put in.
func toLower(s []string) []string {
	for i := 0; i < len(s); i++ {
		s[i] = strings.ToLower(s[i])
	}
	return s
}

// AcquireTokenSilentParameters contains the parameters to acquire a token silently (from cache).
type AcquireTokenSilentParameters struct {
	Scopes           []string
	Account          AccountProvider
	RequestType      requests.RefreshTokenReqType
	ClientCredential msalbase.ClientCredential
}

// TODO(jdoak): augmentAuthenticationParameters == yuck.  Gotta go gotta go!!!!
func (p AcquireTokenSilentParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	authParams.Scopes = p.Scopes
	authParams.AuthorizationType = msalbase.AuthorizationTypeRefreshTokenExchange
	authParams.HomeaccountID = p.Account.GetHomeAccountID()
}

// AcquireTokenAuthCodeParameters contains the parameters required to acquire an access token using the auth code flow.
// To use PKCE, set the CodeChallengeParameter.
// Code challenges are used to secure authorization code grants; for more information, visit
// https://tools.ietf.org/html/rfc7636.
type AcquireTokenAuthCodeParameters struct {
	Scopes           []string
	Code             string
	Challenge        string
	RequestType      requests.AuthCodeRequestType
	clientCredential msalbase.ClientCredential
}

// AuthCodeURL creates a URL used to acquire an authorization code.
func AuthCodeURL(ctx context.Context, resolver *resolvers.AuthorityEndpoint, clientID, redirectURI string, scopes []string, authParams msalbase.AuthParametersInternal) (string, error) {
	endpoints, err := resolver.ResolveEndpoints(ctx, authParams.AuthorityInfo, "")
	if err != nil {
		return "", err
	}

	baseURL, err := url.Parse(endpoints.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}

	v := url.Values{}
	v.Add("client_id", clientID)
	v.Add("response_type", "code")
	v.Add("redirect_uri", redirectURI)
	v.Add("scope", strings.Join(scopes, " "))

	// There were left over from an implementation that didn't use any of these.  We may
	// need to add them later, but as of now aren't needed.
	/*
		if p.CodeChallenge != "" {
			urlParams.Add("code_challenge", p.CodeChallenge)
		}
		if p.State != "" {
			urlParams.Add("state", p.State)
		}
		if p.ResponseMode != "" {
			urlParams.Add("response_mode", p.ResponseMode)
		}
		if p.Prompt != "" {
			urlParams.Add("prompt", p.Prompt)
		}
		if p.LoginHint != "" {
			urlParams.Add("login_hint", p.LoginHint)
		}
		if p.DomainHint != "" {
			urlParams.Add("domain_hint", p.DomainHint)
		}
		if p.CodeChallengeMethod != "" {
			urlParams.Add("code_challenge_method", p.CodeChallengeMethod)
		}
	*/
	baseURL.RawQuery = v.Encode()
	return baseURL.String(), nil
}

// Base is a base client that provides access to common methods and primatives that
// can be used by multiple clients.
type Base struct {
	rest     *ops.REST
	Token    *requests.Token
	Resolver *resolvers.AuthorityEndpoint
	manager  manager // *storage.Manager or fakeManager in tests

	AuthParams    msalbase.AuthParametersInternal // DO NOT EVER MAKE THIS A POINTER! See "Note" in New().
	cacheAccessor cache.ExportReplace
}

// New is the constructor for Base.
func New(clientID string, authorityURI string, cacheAccessor cache.ExportReplace) (Base, error) {
	authInfo, err := msalbase.CreateAuthorityInfoFromAuthorityURI(authorityURI, true)
	if err != nil {
		return Base{}, err
	}
	authParams := msalbase.CreateAuthParametersInternal(clientID, authInfo)

	return Base{ // Note: Hey, don't even THINK about making Base into *Base. See "design notes" in public.go and confidential.go
		rest:          rest,
		Token:         token,
		Resolver:      aeResolver,
		AuthParams:    authParams,
		cacheAccessor: noopCacheAccessor{},
		manager:       storage.New(rest.Authority()),
	}, nil
}

func (b Base) AcquireTokenSilent(ctx context.Context, silent AcquireTokenSilentParameters) (msalbase.AuthenticationResult, error) {
	authParams := b.AuthParams // This is a copy, as we dont' have a pointer receiver and authParams is not a pointer.
	toLower(silent.Scopes)
	silent.augmentAuthenticationParameters(&authParams)

	if s, ok := b.manager.(cache.Serializer); ok {
		b.cacheAccessor.Replace(s)
		defer b.cacheAccessor.Export(s)
	}

	storageTokenResponse, err := b.manager.Read(ctx, authParams)
	if err != nil {
		return msalbase.AuthenticationResult{}, err
	}

	result, err := msalbase.CreateAuthenticationResultFromStorageTokenResponse(storageTokenResponse)
	if err != nil {
		if reflect.ValueOf(storageTokenResponse.RefreshToken).IsNil() {
			return msalbase.AuthenticationResult{}, errors.New("no refresh token found")
		}

		var cc msalbase.ClientCredential
		if silent.RequestType == requests.RefreshTokenConfidential {
			cc = silent.ClientCredential
		}

		token, err := b.Token.Refresh(ctx, b.AuthParams, cc, storageTokenResponse.RefreshToken, silent.RequestType)
		if err != nil {
			return msalbase.AuthenticationResult{}, err
		}

		return b.AuthResultFromToken(ctx, authParams, token, true)
	}
	return result, nil
}

func (b Base) AcquireTokenByAuthCode(ctx context.Context, authCodeParams AcquireTokenAuthCodeParameters) (msalbase.AuthenticationResult, error) {
	authParams := b.AuthParams // This is a copy, as we dont' have a pointer receiver and .AuthParams is not a pointer.
	authParams.Scopes = authCodeParams.Scopes
	authParams.Redirecturi = "https://login.microsoftonline.com/common/oauth2/nativeclient"
	authParams.AuthorizationType = msalbase.AuthorizationTypeAuthCode

	var cc msalbase.ClientCredential
	if authCodeParams.RequestType == requests.AuthCodeConfidential {
		cc = authCodeParams.clientCredential
	}

	req, err := requests.NewCodeChallengeRequest(authParams, authCodeParams.RequestType, cc, authCodeParams.Code, authCodeParams.Challenge)
	if err != nil {
		return msalbase.AuthenticationResult{}, err
	}

	token, err := b.Token.AuthCode(ctx, req)
	if err != nil {
		return msalbase.AuthenticationResult{}, err
	}

	return b.AuthResultFromToken(ctx, authParams, token, true)
}

func (b Base) AuthResultFromToken(ctx context.Context, authParams msalbase.AuthParametersInternal, token msalbase.TokenResponse, cacheWrite bool) (msalbase.AuthenticationResult, error) {
	if !cacheWrite {
		return msalbase.CreateAuthenticationResult(token, msalbase.Account{})
	}

	if s, ok := b.manager.(cache.Serializer); ok {
		b.cacheAccessor.Replace(s)
		defer b.cacheAccessor.Export(s)
	}

	account, err := b.manager.Write(authParams, token)
	if err != nil {
		return msalbase.AuthenticationResult{}, err
	}

	return msalbase.CreateAuthenticationResult(token, account)
}

func (b Base) GetAccounts() []msalbase.Account {
	if s, ok := b.manager.(cache.Serializer); ok {
		b.cacheAccessor.Replace(s)
		defer b.cacheAccessor.Export(s)
	}

	accounts, err := b.manager.GetAllAccounts()
	if err != nil {
		return nil
	}
	return accounts
}
