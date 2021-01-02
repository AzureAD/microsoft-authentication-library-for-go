/*
Package public provides a client for authentication of "public" applications. A "public"
application is defined as an app that runs on client devices (android, ios, windows, linux, ...).
These devices are "untrusted" and access resources via web APIs that must authenticate.
*/
package public

/*
Design note:

public.Client uses client.Base as an embedded type. client.Base statically assigns its attributes
during creation. As it doesn't have any pointers in it, anything borrowed from it, such as
Base.AuthParams is a copy that is free to be manipulated here.
*/

// TODO(msal): This should have example code for each method on client using Go's example doc framework.
// base usage details should be includee in the package documentation.

import (
	"context"
	"fmt"
	"net/url"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/client"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/requests"
)

// AuthenticationResult contains the results of one token acquisition operation.
// For details see https://aka.ms/msal-net-authenticationresult
type AuthenticationResult = client.AuthenticationResult

type Account = msalbase.Account

// Options configures the Client's behavior.
type Options struct {
	// Accessor controls cache persistence. By default there is no cache persistence.
	// This can be set with the Cache() option.
	Accessor cache.ExportReplace

	// The host of the Azure Active Directory authority. The default is https://login.microsoftonline.com/common.
	// This can be changed with the Authority() option.
	Authority string
}

func (p *Options) validate() error {
	u, err := url.Parse(p.Authority)
	if err != nil {
		return fmt.Errorf("Authority options cannot be URL parsed: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("Authority(%s) did not start with https://", u.String())
	}
	return nil
}

// Option is an optional argument to the New constructor.
type Option func(o *Options)

// Authority allows for a custom authority to be set. This must be a valid https url.
func Authority(authority string) Option {
	return func(o *Options) {
		o.Authority = authority
	}
}

// Cache allows you to set some type of cache for storing authentication tokens.
func Cache(accessor cache.ExportReplace) Option {
	return func(o *Options) {
		o.Accessor = accessor
	}
}

// Client is a representation of authentication client for public applications as defined in the
// package doc. For more information, visit https://docs.microsoft.com/azure/active-directory/develop/msal-client-applications.
type Client struct {
	client.Base
}

// New is the constructor for Client.
func New(clientID string, options ...Option) (Client, error) {
	opts := Options{Authority: client.AuthorityPublicCloud}

	for _, o := range options {
		o(&opts)
	}
	if err := opts.validate(); err != nil {
		return Client{}, err
	}

	base, err := client.New(clientID, opts.Authority, opts.Accessor, requests.NewToken())
	if err != nil {
		return Client{}, err
	}
	return Client{base}, nil
}

// CreateAuthCodeURL creates a URL used to acquire an authorization code.
func (pca Client) CreateAuthCodeURL(ctx context.Context, clientID, redirectURI string, scopes []string) (string, error) {
	return pca.Base.AuthCodeURL(ctx, clientID, redirectURI, scopes, pca.AuthParams)
}

// AcquireTokenSilentOptions are all the optional settings to an AcquireTokenSilent() call.
// These are set by using various AcquireTokenSilentOption functions.
type AcquireTokenSilentOptions struct {
	// Account represents the account to use. To set, use the SilentAccount() option.
	Account Account
}

// AcquireTokenSilentOption changes options inside AcquireTokenSilentOptions used in .AcquireTokenSilent().
type AcquireTokenSilentOption func(a *AcquireTokenSilentOptions)

// SilentAccount uses the passed account during an AcquireTokenSilent() call.
func SilentAccount(account Account) AcquireTokenSilentOption {
	return func(a *AcquireTokenSilentOptions) {
		a.Account = account
	}
}

// AcquireTokenSilent acquires a token from either the cache or using a refresh token.
func (pca Client) AcquireTokenSilent(ctx context.Context, scopes []string, options ...AcquireTokenSilentOption) (AuthenticationResult, error) {
	opts := AcquireTokenSilentOptions{}
	for _, o := range options {
		o(&opts)
	}

	silentParameters := client.AcquireTokenSilentParameters{
		Scopes:      scopes,
		Account:     opts.Account,
		RequestType: requests.RefreshTokenPublic,
	}

	return pca.Base.AcquireTokenSilent(ctx, silentParameters)
}

// AcquireTokenByUsernamePassword acquires a security token from the authority, via Username/Password Authentication.
// NOTE: this flow is NOT recommended.
func (pca Client) AcquireTokenByUsernamePassword(ctx context.Context, scopes []string, username string, password string) (AuthenticationResult, error) {
	authParams := pca.AuthParams
	authParams.Scopes = scopes
	authParams.AuthorizationType = msalbase.AuthorizationTypeUsernamePassword
	authParams.Username = username
	authParams.Password = password

	token, err := pca.Base.Token.UsernamePassword(ctx, authParams)
	if err != nil {
		return AuthenticationResult{}, nil
	}
	return pca.Base.AuthResultFromToken(ctx, authParams, token, true)
}

// DeviceCode provides the results of the device code flows first stage (containing the code)
// that must be entered on the second device and provides a method to retrieve the AuthenticationResult
// once that code has been entered and verified.
type DeviceCode struct {
	// Result holds the information about the device code (such as the code).
	Result DeviceCodeResult

	ctx        context.Context
	authParams msalbase.AuthParametersInternal
	client     Client
	dc         requests.DeviceCode
}

type DeviceCodeResult = msalbase.DeviceCodeResult

// AuthenticationResult retreives the AuthenticationResult once the user enters the code
// on the second device. Until then it blocks until the .AcquireTokenByDeviceCode() context
// is cancelled or the token expires.
func (d DeviceCode) AuthenticationResult() (AuthenticationResult, error) {
	token, err := d.dc.Token()
	if err != nil {
		return AuthenticationResult{}, err
	}
	return d.client.AuthResultFromToken(d.ctx, d.authParams, token, true)
}

// AcquireTokenByDeviceCode acquires a security token from the authority, by acquiring a device code and using that to acquire the token.
// Users need to create an AcquireTokenDeviceCodeParameters instance and pass it in.
func (pca Client) AcquireTokenByDeviceCode(ctx context.Context, scopes []string) (DeviceCode, error) {
	authParams := pca.AuthParams
	authParams.Scopes = scopes
	authParams.AuthorizationType = msalbase.AuthorizationTypeDeviceCode

	dc, err := pca.Token.DeviceCode(ctx, authParams)
	if err != nil {
		return DeviceCode{}, err
	}

	return DeviceCode{Result: dc.Result, ctx: ctx, authParams: authParams, client: pca, dc: dc}, nil
}

// AcquireTokenByAuthCodeOptions contains the optional parameters used to acquire an access token using the authorization code flow.
type AcquireTokenByAuthCodeOptions struct {
	Code      string
	Challenge string
}

func (a AcquireTokenByAuthCodeOptions) validate() error {
	if a.Code == "" && a.Challenge == "" {
		return nil
	}

	switch "" {
	case a.Code:
		return fmt.Errorf("AcquireTokenByAuthCode: if you set the Challenge, you must set the Code")
	case a.Challenge:
		return fmt.Errorf("AcquireTokenByAuthCode: if you set the Code, you must set the Challenge")
	}
	return nil
}

// AcquireTokenByAuthCodeOption changes options inside AcquireTokenByAuthCodeOptions used in .AcquireTokenByAuthCode().
type AcquireTokenByAuthCodeOption func(a *AcquireTokenByAuthCodeOptions)

// CodeChallenge allows you to provide a code for the .AcquireTokenByAuthCode() call.
func CodeChallenge(code, challenge string) AcquireTokenByAuthCodeOption {
	return func(a *AcquireTokenByAuthCodeOptions) {
		a.Code = code
		a.Challenge = challenge
	}
}

// AcquireTokenByAuthCode is a request to acquire a security token from the authority, using an authorization code.
func (pca Client) AcquireTokenByAuthCode(ctx context.Context, scopes []string, options ...AcquireTokenByAuthCodeOption) (AuthenticationResult, error) {
	opts := AcquireTokenByAuthCodeOptions{}
	for _, o := range options {
		o(&opts)
	}
	if err := opts.validate(); err != nil {
		return AuthenticationResult{}, err
	}

	params := client.AcquireTokenAuthCodeParameters{
		Scopes:      scopes,
		Code:        opts.Code,
		Challenge:   opts.Challenge,
		RequestType: requests.AuthCodePublic,
	}

	return pca.Base.AcquireTokenByAuthCode(ctx, params)
}

// Accounts gets all the accounts in the token cache.
// If there are no accounts in the cache the returned slice is empty.
func (pca Client) Accounts() []Account {
	return pca.GetAccounts()
}
