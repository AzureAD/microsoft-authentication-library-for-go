// Package base contains a "Base" client that is used by the external public.Client and confidential.Client.
// Base holds shared attributes that must be available to both clients and methods that act as
// shared calls.
package base

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/internal/storage"
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
// In all production use it is a *storage.Manager.
type manager interface {
	Read(ctx context.Context, authParameters authority.AuthParams, account shared.Account) (storage.TokenResponse, error)
	Write(authParameters authority.AuthParams, tokenResponse accesstokens.TokenResponse) (shared.Account, error)
	AllAccounts() ([]shared.Account, error)
}

type noopCacheAccessor struct{}

func (n noopCacheAccessor) Replace(cache cache.Unmarshaler) {}
func (n noopCacheAccessor) Export(cache cache.Marshaler)    {}

// AcquireTokenSilentParameters contains the parameters to acquire a token silently (from cache).
type AcquireTokenSilentParameters struct {
	Scopes      []string
	Account     shared.Account
	RequestType accesstokens.AppType
	Credential  *accesstokens.Credential
}

// AcquireTokenAuthCodeParameters contains the parameters required to acquire an access token using the auth code flow.
// To use PKCE, set the CodeChallengeParameter.
// Code challenges are used to secure authorization code grants; for more information, visit
// https://tools.ietf.org/html/rfc7636.
type AcquireTokenAuthCodeParameters struct {
	Scopes     []string
	Code       string
	Challenge  string
	AppType    accesstokens.AppType
	Credential *accesstokens.Credential
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
}

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
	return AuthResult{account, idToken, accessToken, storageTokenResponse.AccessToken.ExpiresOn.T, grantedScopes, nil}, nil
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
		ExpiresOn:     tokenResponse.ExpiresOn.T,
		GrantedScopes: tokenResponse.GrantedScopes.Slice,
	}, nil
}

// Client is a base client that provides access to common methods and primatives that
// can be used by multiple clients.
type Client struct {
	Token   *oauth.Client
	manager manager // *storage.Manager or fakeManager in tests

	AuthParams    authority.AuthParams // DO NOT EVER MAKE THIS A POINTER! See "Note" in New().
	cacheAccessor cache.ExportReplace
}

// Option is an optional argument to the New constructor.
type Option func(c *Client)

// WithCacheAccessor allows you to set some type of cache for storing authentication tokens.
func WithCacheAccessor(ca cache.ExportReplace) Option {
	return func(c *Client) {
		if ca != nil {
			c.cacheAccessor = ca
		}
	}
}

// New is the constructor for Base.
func New(clientID string, authorityURI string, token *oauth.Client, options ...Option) (Client, error) {
	authInfo, err := authority.NewInfoFromAuthorityURI(authorityURI, true)
	if err != nil {
		return Client{}, err
	}
	authParams := authority.NewAuthParams(clientID, authInfo)
	client := Client{ // Note: Hey, don't even THINK about making Base into *Base. See "design notes" in public.go and confidential.go
		Token:         token,
		AuthParams:    authParams,
		cacheAccessor: noopCacheAccessor{},
		manager:       storage.New(token),
	}
	for _, o := range options {
		o(&client)
	}
	return client, nil

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

func (b Client) AcquireTokenSilent(ctx context.Context, silent AcquireTokenSilentParameters) (AuthResult, error) {
	authParams := b.AuthParams // This is a copy, as we dont' have a pointer receiver and authParams is not a pointer.
	toLower(silent.Scopes)
	authParams.Scopes = silent.Scopes
	authParams.AuthorizationType = authority.ATRefreshToken
	authParams.HomeaccountID = silent.Account.HomeAccountID

	if s, ok := b.manager.(cache.Serializer); ok {
		b.cacheAccessor.Replace(s)
		defer b.cacheAccessor.Export(s)
	}

	storageTokenResponse, err := b.manager.Read(ctx, authParams, silent.Account)
	if err != nil {
		return AuthResult{}, err
	}

	result, err := AuthResultFromStorage(storageTokenResponse)
	if err != nil {
		if reflect.ValueOf(storageTokenResponse.RefreshToken).IsNil() {
			return AuthResult{}, errors.New("no refresh token found")
		}

		var cc *accesstokens.Credential
		if silent.RequestType == accesstokens.ATConfidential {
			cc = silent.Credential
		}

		token, err := b.Token.Refresh(ctx, silent.RequestType, b.AuthParams, cc, storageTokenResponse.RefreshToken)
		if err != nil {
			return AuthResult{}, err
		}

		return b.AuthResultFromToken(ctx, authParams, token, true)
	}
	return result, nil
}

func (b Client) AcquireTokenByAuthCode(ctx context.Context, authCodeParams AcquireTokenAuthCodeParameters) (AuthResult, error) {
	authParams := b.AuthParams // This is a copy, as we dont' have a pointer receiver and .AuthParams is not a pointer.
	authParams.Scopes = authCodeParams.Scopes
	authParams.Redirecturi = "https://login.microsoftonline.com/common/oauth2/nativeclient"
	authParams.AuthorizationType = authority.ATAuthCode

	var cc *accesstokens.Credential
	if authCodeParams.AppType == accesstokens.ATConfidential {
		cc = authCodeParams.Credential
	}

	req, err := accesstokens.NewCodeChallengeRequest(authParams, authCodeParams.AppType, cc, authCodeParams.Code, authCodeParams.Challenge)
	if err != nil {
		return AuthResult{}, err
	}

	token, err := b.Token.AuthCode(ctx, req)
	if err != nil {
		return AuthResult{}, err
	}

	return b.AuthResultFromToken(ctx, authParams, token, true)
}

func (b Client) AuthResultFromToken(ctx context.Context, authParams authority.AuthParams, token accesstokens.TokenResponse, cacheWrite bool) (AuthResult, error) {
	if !cacheWrite {
		return NewAuthResult(token, shared.Account{})
	}

	if s, ok := b.manager.(cache.Serializer); ok {
		b.cacheAccessor.Replace(s)
		defer b.cacheAccessor.Export(s)
	}

	account, err := b.manager.Write(authParams, token)
	if err != nil {
		return AuthResult{}, err
	}
	return NewAuthResult(token, account)
}

func (b Client) Accounts() []shared.Account {
	if s, ok := b.manager.(cache.Serializer); ok {
		b.cacheAccessor.Replace(s)
		defer b.cacheAccessor.Export(s)
	}

	accounts, err := b.manager.AllAccounts()
	if err != nil {
		return nil
	}
	return accounts
}

// toLower makes all slice entries lowercase in-place. Returns the same slice that was put in.
func toLower(s []string) []string {
	for i := 0; i < len(s); i++ {
		s[i] = strings.ToLower(s[i])
	}
	return s
}

// convertStrUnixToUTCTime converts a string representation of unix time to a UTC timestamp.
func convertStrUnixToUTCTime(unixTime string) (time.Time, error) {
	timeInt, err := strconv.ParseInt(unixTime, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(timeInt, 0).UTC(), nil
}
