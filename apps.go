// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

/*
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

type noopCacheAccessor struct{}

func (n noopCacheAccessor) Replace(cache cache.Unmarshaler) {}
func (n noopCacheAccessor) Export(cache cache.Marshaler)    {}

// manager provides an internal cache. It is defined to allow faking the cache in tests.
// In all production use it is a *storage.Manager.
type manager interface {
	Read(ctx context.Context, authParameters authority.AuthParams) (msalbase.StorageTokenResponse, error)
	Write(authParameters authority.AuthParams, tokenResponse accesstokens.TokenResponse) (msalbase.Account, error)
	GetAllAccounts() ([]msalbase.Account, error)
}

type clientApplication struct {
	rest    *ops.REST
	token   *requests.Token
	manager manager // *storage.Manager or fakeManager in tests

	clientApplicationParameters *clientApplicationParameters
	cacheAccessor               cache.ExportReplace
}

func newClientApp(clientID string, authority string) (clientApplication, error) {
	params, err := newClientAppParameters(clientID, authority)
	if err != nil {
		return nil, err
	}

	return clientApplication{
		rest:                        rest,
		token:                       token,
		clientApplicationParameters: params,
		cacheAccessor:               noopCacheAccessor{},
		manager:                     storage.New(rest.Authority()),
	}, nil
}

func (client *clientApplication) createAuthCodeURL(ctx context.Context, authCodeURLParameters AuthorizationCodeURLParameters) (string, error) {
	return authCodeURLParameters.createURL(ctx, client.webRequestManager, client.clientApplicationParameters.createAuthenticationParameters())
}

func (client *clientApplication) acquireTokenSilent(ctx context.Context, silent AcquireTokenSilentParameters) (msalbase.AuthenticationResult, error) {
	authParams := client.clientApplicationParameters.createAuthenticationParameters()
	silent.augmentAuthenticationParameters(&authParams)

	// TODO(jdoak): Think about removing this after refactor.
	if s, ok := client.manager.(cache.Serializer); ok {
		client.cacheAccessor.Replace(s)
		defer client.cacheAccessor.Export(s)
	}

	storageTokenResponse, err := client.manager.Read(ctx, authParams)
	if err != nil {
		return msalbase.AuthenticationResult{}, err
	}

	result, err := msalbase.CreateAuthenticationResultFromStorageTokenResponse(storageTokenResponse)
	if err != nil {
		if reflect.ValueOf(storageTokenResponse.RefreshToken).IsNil() {
			return msalbase.AuthenticationResult{}, errors.New("no refresh token found")
		}
		req := requests.NewRefreshTokenExchangeRequest(client.webRequestManager,
			authParams, storageTokenResponse.RefreshToken, silent.requestType)
		if req.RequestType == requests.RefreshTokenConfidential {
			req.ClientCredential = silent.clientCredential
		}
		return client.executeTokenRequestWithCacheWrite(ctx, req, authParams)
	}
	return result, nil
}

func (client *clientApplication) acquireTokenByAuthCode(ctx context.Context, authCodeParams *acquireTokenAuthCodeParameters) (msalbase.AuthenticationResult, error) {
	authParams := client.clientApplicationParameters.createAuthenticationParameters()
	authCodeParams.augmentAuthenticationParameters(&authParams)

	var cc msalbase.ClientCredential
	if authCodeParams.requestType == requests.AuthCodeConfidential {
		cc = authCodeParams.clientCredential
	}

	req, err := requests.NewCodeChallengeRequest(authParams, authCodeParams.requestType, cc, authCodeParams.Code, authCodeParams.CodeChallenge)
	if err != nil {
		return msalbase.AuthenticationResult{}, err
	}

	return client.executeTokenRequestWithCacheWrite(ctx, req, authParams)
}

func (client *clientApplication) executeTokenRequestWithoutCacheWrite(ctx context.Context, req requests.TokenRequester, authParams authority.AuthParams) (AuthenticationResultProvider, error) {
	tokenResponse, err := req.Execute(ctx)
	if err != nil {
		return nil, err
	}
	// TODO(msal expert): This used to pass nil for Account. I'm not sure if that
	// was really valid or not or had hidden bugs (like the GetAccount() call). This
	// is safe from a Go standpoint, but I'm not sure that MSAL doesn't acutally depend
	// on Account here.  If this is ok, I'll just add a bit of documentation here.
	return msalbase.CreateAuthenticationResult(tokenResponse, msalbase.Account{})
}

func (client *clientApplication) executeTokenRequestWithCacheWrite(ctx context.Context, req requests.TokenRequester, authParams authority.AuthParams) (msalbase.AuthenticationResult, error) {
	tokenResponse, err := req.Execute(ctx)
	if err != nil {
		return msalbase.AuthenticationResult{}, err
	}

	if s, ok := client.manager.(cache.Serializer); ok {
		client.cacheAccessor.Replace(s)
		defer client.cacheAccessor.Export(s)
	}

	account, err := client.manager.Write(authParams, tokenResponse)
	if err != nil {
		return msalbase.AuthenticationResult{}, err
	}
	return msalbase.CreateAuthenticationResult(tokenResponse, account)
}

func (client *clientApplication) getAccounts() []msalbase.Account {
	// TODO(jdoak): Think about removing this after refactor.
	if s, ok := client.manager.(cache.Serializer); ok {
		client.cacheAccessor.Replace(s)
		defer client.cacheAccessor.Export(s)
	}

	accounts, err := client.manager.GetAllAccounts()
	if err != nil {
		return nil
	}
	return accounts
}
*/

/*

// PublicClientApplicationOptions configures the PublicClientApplication's behavior.
type PublicClientApplicationOptions struct {
	// Accessor controls cache persistence.
	// By default there is no cache persistence.
	Accessor cache.ExportReplace

	// The host of the Azure Active Directory authority. The default is https://login.microsoftonline.com/common.
	Authority string
}

func (p *PublicClientApplicationOptions) defaults() {
	if p.Authority == "" {
		p.Authority = authorityPublicCloud
	}
}



// PublicClientApplication is a representation of public client applications.
// These are apps that run on devices or desktop computers or in a web browser and are not trusted to safely keep application secrets.
// For more information, visit https://docs.microsoft.com/azure/active-directory/develop/msal-client-applications.
type PublicClientApplication struct {
	clientApplication
}

// NewPublicClientApplication creates a PublicClientApplication instance given a client ID and authority URL.
func NewPublicClientApplication(clientID string, options PublicClientApplicationOptions) (*PublicClientApplication, error) {
	options.defaults()

	clientApp, err := newClientApp(clientID, options.Authority)
	if err != nil {
		return nil, err
	}
	return &PublicClientApplication{
		clientApplication: clientApp,
	}, nil
}

// CreateAuthCodeURL creates a URL used to acquire an authorization code. Users need to call CreateAuthorizationCodeURLParameters and pass it in.
func (pca *PublicClientApplication) CreateAuthCodeURL(ctx context.Context, authCodeURLParameters AuthorizationCodeURLParameters) (string, error) {
	return pca.clientApplication.createAuthCodeURL(ctx, authCodeURLParameters)
}

// AcquireTokenSilent acquires a token from either the cache or using a refresh token
// Users need to create an AcquireTokenSilentParameters instance and pass it in.
func (pca *PublicClientApplication) AcquireTokenSilent(ctx context.Context, scopes []string, options *AcquireTokenSilentOptions) (msalbase.AuthenticationResult, error) {
	silentParameters := CreateAcquireTokenSilentParameters(scopes)
	silentParameters.requestType = requests.RefreshTokenPublic
	if options != nil {
		silentParameters.account = options.Account
	}
	return pca.clientApplication.acquireTokenSilent(ctx, silentParameters)
}

// AcquireTokenByUsernamePassword acquires a security token from the authority, via Username/Password Authentication.
// Users need to create an AcquireTokenUsernamePasswordParameters instance and pass it in.
// NOTE: this flow is NOT recommended.
func (pca *PublicClientApplication) AcquireTokenByUsernamePassword(ctx context.Context, scopes []string, username string, password string) (msalbase.AuthenticationResult, error) {
	authParams := pca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	usernamePasswordParameters := createAcquireTokenUsernamePasswordParameters(scopes, username, password)
	usernamePasswordParameters.augmentAuthenticationParameters(&authParams)

	req := requests.CreateUsernamePasswordRequest(pca.clientApplication.webRequestManager, authParams)
	return pca.clientApplication.executeTokenRequestWithCacheWrite(ctx, req, authParams)
}

// AcquireTokenByDeviceCode acquires a security token from the authority, by acquiring a device code and using that to acquire the token.
// Users need to create an AcquireTokenDeviceCodeParameters instance and pass it in.
func (pca *PublicClientApplication) AcquireTokenByDeviceCode(ctx context.Context, scopes []string, callback func(DeviceCodeResultProvider), options *AcquireTokenByDeviceCodeOptions) (msalbase.AuthenticationResult, error) {
	dcp := createAcquireTokenDeviceCodeParameters(ctx, scopes, callback)
	authParams := pca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	dcp.augmentAuthenticationParameters(&authParams)
	req := createDeviceCodeRequest(dcp.cancelCtx, pca.clientApplication.webRequestManager, authParams, dcp.deviceCodeCallback)
	return pca.clientApplication.executeTokenRequestWithCacheWrite(ctx, req, authParams)
}

// AcquireTokenByAuthCode is a request to acquire a security token from the authority, using an authorization code.
// Users need to create an AcquireTokenAuthCodeParameters instance and pass it in.
func (pca *PublicClientApplication) AcquireTokenByAuthCode(ctx context.Context, scopes []string, options *AcquireTokenByAuthCodeOptions) (msalbase.AuthenticationResult, error) {
	authCodeParams := createAcquireTokenAuthCodeParameters(scopes)
	authCodeParams.requestType = requests.AuthCodePublic
	if options != nil {
		authCodeParams.Code = options.Code
		authCodeParams.CodeChallenge = options.CodeChallenge
	}
	return pca.clientApplication.acquireTokenByAuthCode(ctx, authCodeParams)
}

// Accounts gets all the accounts in the token cache.
// If there are no accounts in the cache the returned slice is empty.
func (pca *PublicClientApplication) Accounts() []msalbase.Account {
	return pca.clientApplication.getAccounts()
}
*/

/*
// AcquireTokenSilentOptions contains the optional parameters to acquire a token silently (from cache).
type AcquireTokenSilentOptions struct {
	// Account specifies the account to use when acquiring a token from the cache.
	// TODO(jdoak): Add an .IsZero() to handle switching out for defaults vs nil checks.
	Account msalbase.Account
}

// AcquireTokenByDeviceCodeOptions contains the optional parameters used to acquire an access token using the device code flow.
type AcquireTokenByDeviceCodeOptions struct {
	// placeholder for future optional args
}

// AcquireTokenByAuthCodeOptions contains the optional parameters used to acquire an access token using the authorization code flow.
type AcquireTokenByAuthCodeOptions struct {
	Code          string
	CodeChallenge string
}
*/

/*
// ConfidentialClientApplicationOptions configures the PublicClientApplication's behavior.
type ConfidentialClientApplicationOptions struct {
	// Accessor controls cache persistence.
	// By default there is no cache persistence.
	Accessor cache.ExportReplace

	// The host of the Azure Active Directory authority. The default is https://login.microsoftonline.com/common.
	Authority string
}

func (c *ConfidentialClientApplicationOptions) defaults() {
	if c.Authority == "" {
		c.Authority = authorityPublicCloud
	}
}

// ConfidentialClientApplication is a representation of confidential client applications.
// These are apps that run on servers (web apps, web API apps, or even service/daemon apps),
// and are capable of safely storing an application secret.
// For more information, visit https://docs.microsoft.com/azure/active-directory/develop/msal-client-applications
type ConfidentialClientApplication struct {
	clientApplication *clientApplication
	clientCredential  msalbase.ClientCredential
}

// NewConfidentialClientApplication creates a ConfidentialClientApplication instance given a client ID, authority URL and client credential.
func NewConfidentialClientApplication(clientID string, clientCredential ClientCredentialProvider, options ConfidentialClientApplicationOptions) (*ConfidentialClientApplication, error) {
	options.defaults()

	cred, err := createInternalClientCredential(clientCredential)
	if err != nil {
		return nil, err
	}

	clientApp, err := newClientApp(clientID, options.Authority)
	if err != nil {
		return nil, err
	}
	return &ConfidentialClientApplication{
		clientApplication: clientApp,
		clientCredential:  cred,
		token:             token,
	}, nil
}

// This is used to convert the user-facing client credential interface to the internal representation of a client credential
func createInternalClientCredential(interfaceCred ClientCredentialProvider) (msalbase.ClientCredential, error) {
	if interfaceCred.GetCredentialType() == msalbase.ClientCredentialSecret {
		return msalbase.CreateClientCredentialFromSecret(interfaceCred.GetSecret())

	}
	if interfaceCred.GetAssertion().ClientCertificate != nil {
		return msalbase.CreateClientCredentialFromCertificateObject(
			interfaceCred.GetAssertion().ClientCertificate), nil
	}
	return msalbase.CreateClientCredentialFromAssertion(interfaceCred.GetAssertion().ClientAssertionJWT)
}

// CreateAuthCodeURL creates a URL used to acquire an authorization code. Users need to call CreateAuthorizationCodeURLParameters and pass it in.
func (cca *ConfidentialClientApplication) CreateAuthCodeURL(ctx context.Context, authCodeURLParameters AuthorizationCodeURLParameters) (string, error) {
	return cca.clientApplication.createAuthCodeURL(ctx, authCodeURLParameters)
}

// AcquireTokenSilent acquires a token from either the cache or using a refresh token
// Users need to create an AcquireTokenSilentParameters instance and pass it in.
func (cca *ConfidentialClientApplication) AcquireTokenSilent(ctx context.Context, scopes []string, options *AcquireTokenSilentOptions) (msalbase.AuthenticationResult, error) {
	silentParameters := CreateAcquireTokenSilentParameters(scopes)
	silentParameters.requestType = requests.RefreshTokenConfidential
	silentParameters.clientCredential = cca.clientCredential
	if options != nil {
		silentParameters.account = options.Account
	}
	return cca.clientApplication.acquireTokenSilent(ctx, silentParameters)
}

// AcquireTokenByAuthCode is a request to acquire a security token from the authority, using an authorization code.
// Users need to create an AcquireTokenAuthCodeParameters instance and pass it in.
func (cca *ConfidentialClientApplication) AcquireTokenByAuthCode(ctx context.Context, scopes []string, options *AcquireTokenByAuthCodeOptions) (msalbase.AuthenticationResult, error) {
	authCodeParams := createAcquireTokenAuthCodeParameters(scopes)
	authCodeParams.requestType = requests.AuthCodeConfidential
	authCodeParams.clientCredential = cca.clientCredential
	if options != nil {
		authCodeParams.Code = options.Code
		authCodeParams.CodeChallenge = options.CodeChallenge
	}
	return cca.clientApplication.acquireTokenByAuthCode(ctx, authCodeParams)

}

// AcquireTokenByClientCredential acquires a security token from the authority, using the client credentials grant.
// Users need to create an AcquireTokenClientCredentialParameters instance and pass it in.
func (cca *ConfidentialClientApplication) AcquireTokenByClientCredential(ctx context.Context, scopes []string) (msalbase.AuthenticationResult, error) {
	authParams := cca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	clientCredParams := createAcquireTokenClientCredentialParameters(scopes)
	clientCredParams.augmentAuthenticationParameters(&authParams)

	token.
	req := requests.CreateClientCredentialRequest(cca.clientApplication.webRequestManager, authParams, cca.clientCredential)
	return cca.clientApplication.executeTokenRequestWithCacheWrite(ctx, req, authParams)
}

// Accounts gets all the accounts in the token cache.
func (cca *ConfidentialClientApplication) Accounts() []msalbase.Account {
	return cca.clientApplication.getAccounts()
}
*/

/*
// deviceCodeRequest stores the values required to request a token from the authority using device code flow
type deviceCodeRequest struct {
	webRequestManager  requests.WebRequestManager
	authParameters     authority.AuthParams
	deviceCodeCallback func(DeviceCodeResultProvider)
	cancelCtx          context.Context
}

// TODO(jdoak): Make deviceCodeCallback func(DeviceCodeResultProvider) a type.

func createDeviceCodeRequest(ctx context.Context, wrm requests.WebRequestManager, params authority.AuthParams, dcc func(DeviceCodeResultProvider)) *deviceCodeRequest {
	return &deviceCodeRequest{wrm, params, dcc, ctx}
}

// Execute performs the token acquisition request and returns a token response or an error
func (req *deviceCodeRequest) Execute(ctx context.Context) (accesstokens.TokenResponse, error) {
	// Resolve authority endpoints
	resolutionManager := requests.CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(ctx, req.authParameters.AuthorityInfo, "")
	if err != nil {
		return accesstokens.TokenResponse{}, err
	}
	req.authParameters.Endpoints = endpoints
	deviceCodeResult, err := req.webRequestManager.GetDeviceCodeResult(ctx, req.authParameters)
	if err != nil {
		return accesstokens.TokenResponse{}, err
	}
	// Let the user do what they want with the device code result
	req.deviceCodeCallback(deviceCodeResult)
	// Using the device code to get the token response
	return req.waitForTokenResponse(ctx, deviceCodeResult)
}

func (req *deviceCodeRequest) waitForTokenResponse(ctx context.Context, deviceCodeResult msalbase.DeviceCodeResult) (accesstokens.TokenResponse, error) {
	// IntervalAddition is used in device code requests to increase the polling interval if there is a slow down error.
	const IntervalAddition = 5

	interval := deviceCodeResult.GetInterval()
	timeRemaining := deviceCodeResult.GetExpiresOn().Sub(time.Now().UTC())

	for timeRemaining.Seconds() > 0.0 {
		select {
		// If this request needs to be canceled, this context is used
		case <-req.cancelCtx.Done():
			return accesstokens.TokenResponse{}, errors.New("token request canceled")
		default:
			tokenResponse, err := req.webRequestManager.GetAccessTokenFromDeviceCodeResult(ctx, req.authParameters, deviceCodeResult)
			if err != nil {
				// If authorization is pending, update the time remaining
				if isErrorAuthorizationPending(err) {
					timeRemaining = deviceCodeResult.GetExpiresOn().Sub(time.Now().UTC())
					// If the device is polling too frequently, need to increase the polling interval
				} else if isErrorSlowDown(err) {
					interval += IntervalAddition
				} else {
					return accesstokens.TokenResponse{}, err
				}
			} else {
				return tokenResponse, nil
			}
			// Making sure the polling happens at the correct interval
			time.Sleep(time.Duration(interval) * time.Second)
		}
	}
	return accesstokens.TokenResponse{}, errors.New("verification code expired before contacting the server")
}
*/
