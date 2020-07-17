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

// CreatePublicClientApplication creates a PublicClientApplication Instance given its parameters, which include client ID and authority info
func CreatePublicClientApplication(clientID string, authority string) (*PublicClientApplication, error) {
	clientApp := createClientApplication(clientID, authority)
	pca := &PublicClientApplication{
		clientApplication: clientApp,
	}
	return pca, nil
}

func (pca *PublicClientApplication) SetHTTPManager(httpManager IHTTPManager) {
	webRequestManager := CreateWebRequestManager(httpManager)
	pca.clientApplication.webRequestManager = webRequestManager
}

func (pca *PublicClientApplication) SetCacheAccessor(accessor CacheAccessor) {
	pca.clientApplication.cacheAccessor = accessor
}

// CreateAuthCodeURL creates a URL used to acquire an authorization code
func (pca *PublicClientApplication) CreateAuthCodeURL(authCodeURLParameters *AuthorizationCodeURLParameters) (string, error) {
	return pca.clientApplication.createAuthCodeURL(authCodeURLParameters)
}

// AcquireTokenSilent stuff
func (pca *PublicClientApplication) AcquireTokenSilent(
	silentParameters *AcquireTokenSilentParameters) (IAuthenticationResult, error) {
	return pca.clientApplication.acquireTokenSilent(silentParameters)
}

// AcquireTokenByUsernamePassword is a non-interactive request to acquire a security token from the authority, via Username/Password Authentication.
func (pca *PublicClientApplication) AcquireTokenByUsernamePassword(
	usernamePasswordParameters *AcquireTokenUsernamePasswordParameters) (IAuthenticationResult, error) {
	authParams := pca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	usernamePasswordParameters.augmentAuthenticationParameters(authParams)
	req := requests.CreateUsernamePasswordRequest(pca.clientApplication.webRequestManager, authParams)
	return pca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

// AcquireTokenByDeviceCode stuff
func (pca *PublicClientApplication) AcquireTokenByDeviceCode(
	deviceCodeParameters *AcquireTokenDeviceCodeParameters) (IAuthenticationResult, error) {
	authParams := pca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	deviceCodeParameters.augmentAuthenticationParameters(authParams)
	req := createDeviceCodeRequest(deviceCodeParameters.cancelCtx, pca.clientApplication.webRequestManager, authParams, deviceCodeParameters.deviceCodeCallback)
	return pca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

// AcquireTokenByAuthCode is a request to acquire a security token from the authority, using an authorization code
func (pca *PublicClientApplication) AcquireTokenByAuthCode(
	authCodeParams *AcquireTokenAuthCodeParameters) (IAuthenticationResult, error) {
	return pca.clientApplication.acquireTokenByAuthCode(authCodeParams)
}

func (pca *PublicClientApplication) GetAccounts() []IAccount {
	return pca.clientApplication.getAccounts()
}
