// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"context"
	"net/http"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
)

// PublicClientApplication is a representation of public client applications.
// These are apps that run on devices or desktop computers or in a web browser and are not trusted to safely keep application secrets.
// For more information, visit https://docs.microsoft.com/azure/active-directory/develop/msal-client-applications.
type PublicClientApplication struct {
	clientApplication *clientApplication
}

// PublicClientApplicationOptions configures the PublicClientApplication's behavior.
type PublicClientApplicationOptions struct {
	// Accessor controls cache persistence.
	// By default there is no cache persistence.
	Accessor CacheAccessor

	// Client sets the transport for making HTTP requests.
	// Leave this as nil to use the default HTTP transport.
	Client HTTPClient
}

// DefaultPublicClientApplicationOptions returns an instance of PublicClientApplicationOptions initialized with default values.
func DefaultPublicClientApplicationOptions() PublicClientApplicationOptions {
	return PublicClientApplicationOptions{
		Client: http.DefaultClient,
	}
}

// NewPublicClientApplication creates a PublicClientApplication instance given a client ID and authority URL.
// Pass nil for options to accept the default values; this is the same as passing the result
// from a call to DefaultPublicClientApplicationOptions().
func NewPublicClientApplication(clientID string, authority string, options *PublicClientApplicationOptions) *PublicClientApplication {
	clientApp := createClientApplication(clientID, authority)
	return &PublicClientApplication{
		clientApplication: clientApp,
	}
}

// CreateAuthCodeURL creates a URL used to acquire an authorization code. Users need to call CreateAuthorizationCodeURLParameters and pass it in.
func (pca *PublicClientApplication) CreateAuthCodeURL(authCodeURLParameters *AuthorizationCodeURLParameters) (string, error) {
	return pca.clientApplication.createAuthCodeURL(authCodeURLParameters)
}

// AcquireTokenSilent acquires a token from either the cache or using a refresh token
// Users need to create an AcquireTokenSilentParameters instance and pass it in.
func (pca *PublicClientApplication) AcquireTokenSilent(ctx context.Context, scopes []string, options *AcquireTokenSilentOptions) (*msalbase.AuthenticationResult, error) {
	silentParameters.requestType = requests.RefreshTokenPublic
	return pca.clientApplication.acquireTokenSilent(silentParameters)
}

// AcquireTokenByUsernamePassword acquires a security token from the authority, via Username/Password Authentication.
// Users need to create an AcquireTokenUsernamePasswordParameters instance and pass it in.
// NOTE: this flow is NOT recommended.
func (pca *PublicClientApplication) AcquireTokenByUsernamePassword(
	ctx context.Context,
	usernamePasswordParameters *AcquireTokenUsernamePasswordParameters) (*msalbase.AuthenticationResult, error) {
	authParams := pca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	usernamePasswordParameters.augmentAuthenticationParameters(authParams)
	req := requests.CreateUsernamePasswordRequest(pca.clientApplication.webRequestManager, authParams)
	return pca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

// AcquireTokenByDeviceCode acquires a security token from the authority, by acquiring a device code and using that to acquire the token.
// Users need to create an AcquireTokenDeviceCodeParameters instance and pass it in.
func (pca *PublicClientApplication) AcquireTokenByDeviceCode(ctx context.Context, scopes []string, callback func(DeviceCodeResultProvider), options *AcquireTokenDeviceCodeOptions) (*msalbase.AuthenticationResult, error) {
	authParams := pca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	deviceCodeParameters.augmentAuthenticationParameters(authParams)
	req := createDeviceCodeRequest(deviceCodeParameters.cancelCtx, pca.clientApplication.webRequestManager, authParams, deviceCodeParameters.deviceCodeCallback)
	return pca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

// AcquireTokenByAuthCode is a request to acquire a security token from the authority, using an authorization code.
// Users need to create an AcquireTokenAuthCodeParameters instance and pass it in.
func (pca *PublicClientApplication) AcquireTokenByAuthCode(
	ctx context.Context,
	authCodeParams *AcquireTokenAuthCodeParameters) (*msalbase.AuthenticationResult, error) {
	authCodeParams.requestType = requests.AuthCodePublic
	return pca.clientApplication.acquireTokenByAuthCode(authCodeParams)
}

// Accounts gets all the accounts in the token cache.
// If there are no accounts in the cache the returned slice is empty.
func (pca *PublicClientApplication) Accounts() []*msalbase.Account {
	return pca.clientApplication.getAccounts()
}
