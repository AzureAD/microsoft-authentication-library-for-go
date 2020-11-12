// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
)

// PublicClientApplication is a representation of public client applications.
// These are apps that run on devices or desktop computers or in a web browser and are not trusted to safely keep application secrets.
// For more information, visit https://docs.microsoft.com/azure/active-directory/develop/msal-client-applications.
type PublicClientApplication struct {
	clientApplication *clientApplication
}

// CreatePublicClientApplication creates a PublicClientApplication instance given a client ID and authority URL.
func CreatePublicClientApplication(clientID string, authority string) (*PublicClientApplication, error) {
	clientApp, err := createClientApplication(clientID, authority)
	if err != nil {
		return nil, err
	}
	return &PublicClientApplication{clientApplication: clientApp}, nil
}

//SetHTTPManager allows users to use their own implementation of HTTPManager.
func (pca *PublicClientApplication) SetHTTPManager(httpManager HTTPManager) {
	webRequestManager := createWebRequestManager(httpManager)
	pca.clientApplication.webRequestManager = webRequestManager
}

//SetCacheAccessor allows users to use an implementation of CacheAccessor to handle cache persistence.
func (pca *PublicClientApplication) SetCacheAccessor(accessor CacheAccessor) {
	pca.clientApplication.cacheAccessor = accessor
}

// CreateAuthCodeURL creates a URL used to acquire an authorization code. Users need to call CreateAuthorizationCodeURLParameters and pass it in.
func (pca *PublicClientApplication) CreateAuthCodeURL(authCodeURLParameters *AuthorizationCodeURLParameters) (string, error) {
	return pca.clientApplication.createAuthCodeURL(authCodeURLParameters)
}

// AcquireTokenSilent acquires a token from either the cache or using a refresh token
// Users need to create an AcquireTokenSilentParameters instance and pass it in.
func (pca *PublicClientApplication) AcquireTokenSilent(params AcquireTokenSilentParameters) (AuthenticationResultProvider, error) {
	params.requestType = requests.RefreshTokenPublic
	return pca.clientApplication.acquireTokenSilent(params)
}

// AcquireTokenByUsernamePassword acquires a security token from the authority, via Username/Password Authentication.
// Users need to create an AcquireTokenUsernamePasswordParameters instance and pass it in.
// NOTE: this flow is NOT recommended.
func (pca *PublicClientApplication) AcquireTokenByUsernamePassword(atupp *AcquireTokenUsernamePasswordParameters) (AuthenticationResultProvider, error) {
	authParams := pca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	atupp.augmentAuthenticationParameters(&authParams)
	req := requests.CreateUsernamePasswordRequest(pca.clientApplication.webRequestManager, authParams)
	return pca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

// AcquireTokenByDeviceCode acquires a security token from the authority, by acquiring a device code and using that to acquire the token.
// Users need to create an AcquireTokenDeviceCodeParameters instance and pass it in.
func (pca *PublicClientApplication) AcquireTokenByDeviceCode(dcp *AcquireTokenDeviceCodeParameters) (AuthenticationResultProvider, error) {
	authParams := pca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	dcp.augmentAuthenticationParameters(&authParams)
	req := createDeviceCodeRequest(dcp.cancelCtx, pca.clientApplication.webRequestManager, authParams, dcp.deviceCodeCallback)
	return pca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

// AcquireTokenByAuthCode is a request to acquire a security token from the authority, using an authorization code.
// Users need to create an AcquireTokenAuthCodeParameters instance and pass it in.
func (pca *PublicClientApplication) AcquireTokenByAuthCode(atacp *AcquireTokenAuthCodeParameters) (AuthenticationResultProvider, error) {
	atacp.requestType = requests.AuthCodePublic
	return pca.clientApplication.acquireTokenByAuthCode(atacp)
}

// GetAccounts gets all the accounts in the token cache.
func (pca *PublicClientApplication) GetAccounts() []AccountProvider {
	return pca.clientApplication.getAccounts()
}
