// Package client contains a "Base" client that is used by the external public.Client and confidential.Client.
// Base holds shared attributes that must be available to both clients and methods that act as
// shared calls.
package client

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/apps/cache"
	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/apps/internal/client/internal/storage"
	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/apps/internal/requests"
)

const (
	// AuthorityPublicCloud is the default AAD authority host
	AuthorityPublicCloud = "https://login.microsoftonline.com/common"
	scopeSeparator       = " "
)

// manager provides an internal cache. It is defined to allow faking the cache in tests.
// In all production use it is a *storage.Manager.
type manager interface {
	Read(ctx context.Context, authParameters msalbase.AuthParametersInternal) (storage.StorageTokenResponse, error)
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

// AcquireTokenSilentParameters contains the parameters to acquire a token silently (from cache).
type AcquireTokenSilentParameters struct {
	Scopes      []string
	Account     AccountProvider
	RequestType requests.RefreshTokenReqType
	Credential  *msalbase.Credential
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
	Scopes      []string
	Code        string
	Challenge   string
	RequestType requests.AuthCodeRequestType
	Credential  *msalbase.Credential
}

// AuthenticationResult contains the results of one token acquisition operation in PublicClientApplication
// or ConfidentialClientApplication. For details see https://aka.ms/msal-net-authenticationresult
type AuthenticationResult struct {
	Account        msalbase.Account
	IDToken        msalbase.IDToken
	AccessToken    string
	ExpiresOn      time.Time
	GrantedScopes  []string
	DeclinedScopes []string
}

// CreateAuthenticationResultFromStorageTokenResponse creates an authenication result from a storage token response (which is generated from the cache).
func CreateAuthenticationResultFromStorageTokenResponse(storageTokenResponse storage.StorageTokenResponse) (AuthenticationResult, error) {
	if err := storageTokenResponse.AccessToken.Validate(); err != nil {
		return AuthenticationResult{}, fmt.Errorf("problem with access token in StorageTokenResponse: %w", err)
	}

	account := storageTokenResponse.Account
	accessToken := storageTokenResponse.AccessToken.Secret
	expiresOn, err := convertStrUnixToUTCTime(storageTokenResponse.AccessToken.ExpiresOnUnixTimestamp)
	if err != nil {
		return AuthenticationResult{}, fmt.Errorf("token response from server is invalid because expires_in is set to %q", storageTokenResponse.AccessToken.ExpiresOnUnixTimestamp)
	}
	grantedScopes := strings.Split(storageTokenResponse.AccessToken.Scopes, scopeSeparator)

	// Checking if there was an ID token in the cache; this will throw an error in the case of confidential client applications.
	var idToken msalbase.IDToken
	if !storageTokenResponse.IDToken.IsZero() {
		idToken, err = msalbase.NewIDToken(storageTokenResponse.IDToken.Secret)
		if err != nil {
			return AuthenticationResult{}, err
		}
	}
	return AuthenticationResult{account, idToken, accessToken, expiresOn, grantedScopes, nil}, nil
}

// CreateAuthenticationResult creates an AuthenticationResult.
// TODO(jdoak): (maybe, we did a refactor): Make this a method on TokenResponse() that takes only 1 arge, Account.
func CreateAuthenticationResult(tokenResponse msalbase.TokenResponse, account msalbase.Account) (AuthenticationResult, error) {
	if len(tokenResponse.DeclinedScopes) > 0 {
		return AuthenticationResult{}, fmt.Errorf("token response failed because declined scopes are present: %s", strings.Join(tokenResponse.DeclinedScopes, ","))
	}
	return AuthenticationResult{
		Account:       account,
		IDToken:       tokenResponse.IDToken,
		AccessToken:   tokenResponse.AccessToken,
		ExpiresOn:     tokenResponse.ExpiresOn,
		GrantedScopes: tokenResponse.GrantedScopes,
	}, nil
}

//GetAccessToken returns the access token of the authentication result
func (ar AuthenticationResult) GetAccessToken() string {
	return ar.AccessToken
}

// GetAccount returns the account of the authentication result
func (ar AuthenticationResult) GetAccount() msalbase.Account {
	return ar.Account
}

// Base is a base client that provides access to common methods and primatives that
// can be used by multiple clients.
type Base struct {
	Token   *requests.Token
	manager manager // *storage.Manager or fakeManager in tests

	AuthParams    msalbase.AuthParametersInternal // DO NOT EVER MAKE THIS A POINTER! See "Note" in New().
	cacheAccessor cache.ExportReplace
}

// New is the constructor for Base.
func New(clientID string, authorityURI string, cacheAccessor cache.ExportReplace, token *requests.Token) (Base, error) {
	authInfo, err := msalbase.CreateAuthorityInfoFromAuthorityURI(authorityURI, true)
	if err != nil {
		return Base{}, err
	}
	authParams := msalbase.CreateAuthParametersInternal(clientID, authInfo)

	return Base{ // Note: Hey, don't even THINK about making Base into *Base. See "design notes" in public.go and confidential.go
		Token:         token,
		AuthParams:    authParams,
		cacheAccessor: noopCacheAccessor{},
		manager:       storage.New(token),
	}, nil
}

// AuthCodeURL creates a URL used to acquire an authorization code.
func (b Base) AuthCodeURL(ctx context.Context, clientID, redirectURI string, scopes []string, authParams msalbase.AuthParametersInternal) (string, error) {
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

func (b Base) AcquireTokenSilent(ctx context.Context, silent AcquireTokenSilentParameters) (AuthenticationResult, error) {
	authParams := b.AuthParams // This is a copy, as we dont' have a pointer receiver and authParams is not a pointer.
	toLower(silent.Scopes)
	silent.augmentAuthenticationParameters(&authParams)

	if s, ok := b.manager.(cache.Serializer); ok {
		b.cacheAccessor.Replace(s)
		defer b.cacheAccessor.Export(s)
	}

	storageTokenResponse, err := b.manager.Read(ctx, authParams)
	if err != nil {
		return AuthenticationResult{}, err
	}

	result, err := CreateAuthenticationResultFromStorageTokenResponse(storageTokenResponse)
	if err != nil {
		if reflect.ValueOf(storageTokenResponse.RefreshToken).IsNil() {
			return AuthenticationResult{}, errors.New("no refresh token found")
		}

		var cc *msalbase.Credential
		if silent.RequestType == requests.RefreshTokenConfidential {
			cc = silent.Credential
		}

		token, err := b.Token.Refresh(ctx, b.AuthParams, cc, storageTokenResponse.RefreshToken, silent.RequestType)
		if err != nil {
			return AuthenticationResult{}, err
		}

		return b.AuthResultFromToken(ctx, authParams, token, true)
	}
	return result, nil
}

func (b Base) AcquireTokenByAuthCode(ctx context.Context, authCodeParams AcquireTokenAuthCodeParameters) (AuthenticationResult, error) {
	authParams := b.AuthParams // This is a copy, as we dont' have a pointer receiver and .AuthParams is not a pointer.
	authParams.Scopes = authCodeParams.Scopes
	authParams.Redirecturi = "https://login.microsoftonline.com/common/oauth2/nativeclient"
	authParams.AuthorizationType = msalbase.AuthorizationTypeAuthCode

	var cc *msalbase.Credential
	if authCodeParams.RequestType == requests.AuthCodeConfidential {
		cc = authCodeParams.Credential
	}

	req, err := requests.NewCodeChallengeRequest(authParams, authCodeParams.RequestType, cc, authCodeParams.Code, authCodeParams.Challenge)
	if err != nil {
		return AuthenticationResult{}, err
	}

	token, err := b.Token.AuthCode(ctx, req)
	if err != nil {
		return AuthenticationResult{}, err
	}

	return b.AuthResultFromToken(ctx, authParams, token, true)
}

func (b Base) AuthResultFromToken(ctx context.Context, authParams msalbase.AuthParametersInternal, token msalbase.TokenResponse, cacheWrite bool) (AuthenticationResult, error) {
	if !cacheWrite {
		return CreateAuthenticationResult(token, msalbase.Account{})
	}

	if s, ok := b.manager.(cache.Serializer); ok {
		b.cacheAccessor.Replace(s)
		defer b.cacheAccessor.Export(s)
	}

	account, err := b.manager.Write(authParams, token)
	if err != nil {
		return AuthenticationResult{}, err
	}

	return CreateAuthenticationResult(token, account)
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
