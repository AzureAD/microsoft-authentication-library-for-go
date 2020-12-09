// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"context"
	"net/url"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
)

// AcquireTokenAuthCodeParameters contains the parameters required to acquire an access token using the auth code flow.
// To use PKCE, set the CodeChallengeParameter.
// Code challenges are used to secure authorization code grants; for more information, visit
// https://tools.ietf.org/html/rfc7636.
type acquireTokenAuthCodeParameters struct {
	commonParameters acquireTokenCommonParameters
	Code             string
	CodeChallenge    string
	clientCredential msalbase.ClientCredential
	requestType      requests.AuthCodeRequestType
}

// createAcquireTokenAuthCodeParameters creates an AcquireTokenAuthCodeParameters instance.
// Pass in the scopes required, the redirect URI for your application.
func createAcquireTokenAuthCodeParameters(scopes []string) *acquireTokenAuthCodeParameters {
	return &acquireTokenAuthCodeParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
	}
}

func (p *acquireTokenAuthCodeParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.Redirecturi = "https://login.microsoftonline.com/common/oauth2/nativeclient"
	authParams.AuthorizationType = msalbase.AuthorizationTypeAuthCode
}

// AcquireTokenClientCredentialParameters contains the parameters required to acquire an access token using the client credential flow.
type acquireTokenClientCredentialParameters struct {
	commonParameters acquireTokenCommonParameters
}

// CreateAcquireTokenClientCredentialParameters creates an AcquireTokenClientCredentialParameters instance.
// Pass in the scopes required.
func createAcquireTokenClientCredentialParameters(scopes []string) acquireTokenClientCredentialParameters {
	return acquireTokenClientCredentialParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
	}
}

func (p *acquireTokenClientCredentialParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.AuthorizationType = msalbase.AuthorizationTypeClientCredentials
}

type acquireTokenCommonParameters struct {
	scopes []string
}

func createAcquireTokenCommonParameters(scopes []string) acquireTokenCommonParameters {
	loweredScopes := []string{}
	for _, s := range scopes {
		s = strings.ToLower(s)
		loweredScopes = append(loweredScopes, s)
	}
	return acquireTokenCommonParameters{
		scopes: loweredScopes,
	}
}

func (p *acquireTokenCommonParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	authParams.Scopes = p.scopes
}

// acquireTokenDeviceCodeParameters contains the parameters required to acquire an access token using the device code flow.
type acquireTokenDeviceCodeParameters struct {
	commonParameters   acquireTokenCommonParameters
	deviceCodeCallback func(DeviceCodeResultProvider)
	cancelCtx          context.Context
}

// CreateAcquireTokenDeviceCodeParameters creates an AcquireTokenDeviceCodeParameters instance.
// This flow is designed for devices that do not have access to a browser or have input constraints.
// The authorization server issues a DeviceCode object with a verification code, an end-user code, and the end-user verification URI.
// The DeviceCode object is provided through the DeviceCodeResultProvider callback, and the end-user should be instructed to use
// another device to navigate to the verification URI to input credentials. Since the client cannot receive incoming requests,
// MSAL polls the authorization server repeatedly until the end-user completes input of credentials. Use cancelCtx to cancel the polling.
func createAcquireTokenDeviceCodeParameters(cancelCtx context.Context, scopes []string, deviceCodeCallback func(DeviceCodeResultProvider)) acquireTokenDeviceCodeParameters {
	return acquireTokenDeviceCodeParameters{
		commonParameters:   createAcquireTokenCommonParameters(scopes),
		deviceCodeCallback: deviceCodeCallback,
		cancelCtx:          cancelCtx,
	}
}

func (p acquireTokenDeviceCodeParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.AuthorizationType = msalbase.AuthorizationTypeDeviceCode
}

// AuthorizationCodeURLParameters has the parameters to create the URL to generate an authorization code.
type AuthorizationCodeURLParameters struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	ResponseMode        string
	State               string
	Prompt              string
	LoginHint           string
	DomainHint          string
	CodeChallenge       string
	CodeChallengeMethod string
	Scopes              []string
}

// CreateAuthorizationCodeURLParameters creates an AuthorizationCodeURLParameters instance. These are the basic required parameters to create this URL.
// However, if you want other parameters to be in the URL, you can just set the fields of the struct.
func CreateAuthorizationCodeURLParameters(clientID string, redirectURI string, scopes []string) AuthorizationCodeURLParameters {
	// DefaultAuthCodeResponseType is the response type for authorization code requests.
	const DefaultAuthCodeResponseType = "code"

	return AuthorizationCodeURLParameters{
		ClientID:     clientID,
		ResponseType: DefaultAuthCodeResponseType,
		RedirectURI:  redirectURI,
		Scopes:       scopes,
	}
}

//createURL creates the URL required to generate an authorization code from the parameters
func (p AuthorizationCodeURLParameters) createURL(ctx context.Context, wrm requests.WebRequestManager, authParams msalbase.AuthParametersInternal) (string, error) {
	resolutionManager := requests.CreateAuthorityEndpointResolutionManager(wrm)
	endpoints, err := resolutionManager.ResolveEndpoints(ctx, authParams.AuthorityInfo, "")
	if err != nil {
		return "", err
	}
	baseURL, err := url.Parse(endpoints.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	urlParams := url.Values{}
	urlParams.Add("client_id", p.ClientID)
	urlParams.Add("response_type", p.ResponseType)
	urlParams.Add("redirect_uri", p.RedirectURI)
	urlParams.Add("scope", p.getSeparatedScopes())
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
	baseURL.RawQuery = urlParams.Encode()
	return baseURL.String(), nil
}

func (p AuthorizationCodeURLParameters) getSeparatedScopes() string {
	return msalbase.ConcatenateScopes(p.Scopes)
}

// TODO(jdoak): determine in the long run if this is even needed. Looks like
// a hold over from a language conversion.  This doesn't do anything but use
// applicationCommonParameters, which probably means it has no validity as its
// own type.
type clientApplicationParameters struct {
	commonParameters *applicationCommonParameters
}

func createClientApplicationParameters(clientID, authorityURI string) (*clientApplicationParameters, error) {
	// NOTE: I moved setADDAuthority here.  It called a method that was only
	// used on the output of this function, which is only called here.  It also
	// ignored the error output. That seems buggy (anytime you ignore an error, must document why).
	cp, err := createApplicationCommonParameters(clientID, authorityURI)
	if err != nil {
		return nil, err
	}
	return &clientApplicationParameters{
		commonParameters: cp,
	}, nil
}

func (p *clientApplicationParameters) validate() error {
	err := p.commonParameters.validate()
	return err
}

func (p *clientApplicationParameters) createAuthenticationParameters() msalbase.AuthParametersInternal {
	return p.commonParameters.createAuthenticationParameters()
}

type applicationCommonParameters struct {
	clientID      string
	authorityInfo msalbase.AuthorityInfo
}

func createApplicationCommonParameters(clientID, authorityURI string) (*applicationCommonParameters, error) {
	a, err := msalbase.CreateAuthorityInfoFromAuthorityURI(authorityURI, true)
	if err != nil {
		return nil, err
	}
	return &applicationCommonParameters{
		clientID:      clientID,
		authorityInfo: a,
	}, nil
}

func (p *applicationCommonParameters) validate() error {
	return nil
}

func (p *applicationCommonParameters) createAuthenticationParameters() msalbase.AuthParametersInternal {
	return msalbase.CreateAuthParametersInternal(p.clientID, p.authorityInfo)
}

// AcquireTokenSilentParameters contains the parameters to acquire a token silently (from cache).
type AcquireTokenSilentParameters struct {
	commonParameters acquireTokenCommonParameters
	account          AccountProvider
	requestType      requests.RefreshTokenReqType
	clientCredential msalbase.ClientCredential
}

// CreateAcquireTokenSilentParameters creates an AcquireTokenSilentParameters instance with an empty account.
// This can be used in the case where tokens are acquired as the application instelf.
func CreateAcquireTokenSilentParameters(scopes []string) AcquireTokenSilentParameters {
	return AcquireTokenSilentParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		account:          msalbase.Account{},
	}
}

// CreateAcquireTokenSilentParametersWithAccount creates an AcquireTokenSilentParameters instance from an account.
// This account can be pulled from the cache by calling GetAccounts
func CreateAcquireTokenSilentParametersWithAccount(scopes []string, account AccountProvider) AcquireTokenSilentParameters {
	return AcquireTokenSilentParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		account:          account,
	}
}

func (p AcquireTokenSilentParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.AuthorizationType = msalbase.AuthorizationTypeRefreshTokenExchange
	authParams.HomeaccountID = p.account.GetHomeAccountID()
}

// AcquireTokenUsernamePasswordParameters contains the parameters required to acquire an access token using a username and password.
type acquireTokenUsernamePasswordParameters struct {
	commonParameters acquireTokenCommonParameters
	username         string
	password         string
}

// CreateAcquireTokenUsernamePasswordParameters creates an AcquireTokenUsernamePasswordParameters instance.
// Pass in the scopes as well as the user's username and password.
func createAcquireTokenUsernamePasswordParameters(scopes []string, username string, password string) acquireTokenUsernamePasswordParameters {
	return acquireTokenUsernamePasswordParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		username:         username,
		password:         password,
	}
}

func (p acquireTokenUsernamePasswordParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.AuthorizationType = msalbase.AuthorizationTypeUsernamePassword
	authParams.Username = p.username
	authParams.Password = p.password
}
