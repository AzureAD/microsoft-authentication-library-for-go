// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
)

// PublicClientApplication is used to acquire tokens in desktop or mobile applications (Desktop / UWP / Xamarin.iOS / Xamarin.Android).
// public client applications are not trusted to safely keep application secrets, and therefore they only access Web APIs in the name of the user only
// (they only support public client flows). For details see https://aka.ms/msal-net-client-applications
type PublicClientApplication struct {
	clientApplication *clientApplication
}

// CreatePublicClientApplication creates a PublicClientApplication instance given a client ID and authority info
func CreatePublicClientApplication(clientID string, authority string) (*PublicClientApplication, error) {
	clientApp := createClientApplication(clientID, authority)
	pca := &PublicClientApplication{
		clientApplication: clientApp,
	}
	return pca, nil
}

//SetHTTPManager allows users to use their own implementation of HTTPManager
func (pca *PublicClientApplication) SetHTTPManager(httpManager HTTPManager) {
	webRequestManager := createWebRequestManager(httpManager)
	pca.clientApplication.webRequestManager = webRequestManager
}

//SetCacheAccessor allows users to use an implementation of CacheAccessor to handle cache persistence
func (pca *PublicClientApplication) SetCacheAccessor(accessor CacheAccessor) {
	pca.clientApplication.cacheAccessor = accessor
}

// CreateAuthCodeURL creates a URL used to acquire an authorization code
func (pca *PublicClientApplication) CreateAuthCodeURL(authCodeURLParameters *AuthorizationCodeURLParameters) (string, error) {
	return pca.clientApplication.createAuthCodeURL(authCodeURLParameters)
}

//AcquireTokenSilent acquires a token from either the cache or using a refresh token
func (pca *PublicClientApplication) AcquireTokenSilent(
	silentParameters *AcquireTokenSilentParameters) (AuthenticationResultInterfacer, error) {
	return pca.clientApplication.acquireTokenSilent(silentParameters)
}

// AcquireTokenByUsernamePassword acquires a security token from the authority, via Username/Password Authentication.
func (pca *PublicClientApplication) AcquireTokenByUsernamePassword(
	usernamePasswordParameters *AcquireTokenUsernamePasswordParameters) (AuthenticationResultInterfacer, error) {
	authParams := pca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	usernamePasswordParameters.augmentAuthenticationParameters(authParams)
	req := requests.CreateUsernamePasswordRequest(pca.clientApplication.webRequestManager, authParams)
	return pca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

// AcquireTokenByDeviceCode acquires a security token from the authority, by acquiring a device code and using that to acquire the token.
func (pca *PublicClientApplication) AcquireTokenByDeviceCode(
	deviceCodeParameters *AcquireTokenDeviceCodeParameters) (AuthenticationResultInterfacer, error) {
	authParams := pca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	deviceCodeParameters.augmentAuthenticationParameters(authParams)
	req := createDeviceCodeRequest(deviceCodeParameters.cancelCtx, pca.clientApplication.webRequestManager, authParams, deviceCodeParameters.deviceCodeCallback)
	return pca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

// AcquireTokenByAuthCode is a request to acquire a security token from the authority, using an authorization code
func (pca *PublicClientApplication) AcquireTokenByAuthCode(
	authCodeParams *AcquireTokenAuthCodeParameters) (AuthenticationResultInterfacer, error) {
	authCodeParams.requestType = requests.AuthCodePublicClient
	return pca.clientApplication.acquireTokenByAuthCode(authCodeParams)
}

//GetAccounts gets all the accounts in the cache
func (pca *PublicClientApplication) GetAccounts() []AccountInterfacer {
	return pca.clientApplication.getAccounts()
}
