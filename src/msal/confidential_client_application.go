// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"

type ConfidentialClientApplication struct {
	clientApplication *clientApplication
}

func CreateConfidentialClientApplication(clientID string, authority string) *ConfidentialClientApplication {
	clientApp := createClientApplication(clientID, authority)
	cca := &ConfidentialClientApplication{
		clientApplication: clientApp,
	}
	return cca
}

func (cca *ConfidentialClientApplication) SetHTTPManager(httpManager IHTTPManager) {
	webRequestManager := CreateWebRequestManager(httpManager)
	cca.clientApplication.webRequestManager = webRequestManager
}

func (cca *ConfidentialClientApplication) SetCacheAccessor(accessor CacheAccessor) {
	cca.clientApplication.cacheAccessor = accessor
}

// CreateAuthCodeURL creates a URL used to acquire an authorization code
func (cca *ConfidentialClientApplication) CreateAuthCodeURL(authCodeURLParameters *AuthorizationCodeURLParameters) (string, error) {
	return cca.clientApplication.createAuthCodeURL(authCodeURLParameters)
}

func (cca *ConfidentialClientApplication) AcquireTokenSilent(
	silentParameters *AcquireTokenSilentParameters) (IAuthenticationResult, error) {
	return cca.clientApplication.acquireTokenSilent(silentParameters)
}

func (cca *ConfidentialClientApplication) AcquireTokenByAuthCode(
	authCodeParams *AcquireTokenAuthCodeParameters) (IAuthenticationResult, error) {
	return cca.clientApplication.acquireTokenByAuthCode(authCodeParams)

}

func (cca *ConfidentialClientApplication) AcquireTokenByClientSecret(
	clientCredParams *AcquireTokenClientCredentialsParameters) (IAuthenticationResult, error) {
	authParams := cca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	clientCredParams.augmentAuthenticationParameters(authParams)
	req := requests.CreateClientCredentialsRequest(
		cca.clientApplication.webRequestManager, authParams, clientCredParams.clientSecret)
	return cca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

func (cca *ConfidentialClientApplication) GetAccounts() []IAccount {
	return cca.clientApplication.getAccounts()
}
