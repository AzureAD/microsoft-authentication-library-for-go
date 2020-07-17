// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

type ConfidentialClientApplication struct {
	clientApp *clientApplication
}

func CreateConfidentialClientApplication(clientID string, authority string) *ConfidentialClientApplication {
	clientApp := createClientApplication(clientID, authority)
	cca := &ConfidentialClientApplication{
		clientApp: clientApp,
	}
	return cca
}

func (cca *ConfidentialClientApplication) SetHTTPManager(httpManager IHTTPManager) {
	webRequestManager := CreateWebRequestManager(httpManager)
	cca.clientApp.webRequestManager = webRequestManager
}

func (cca *ConfidentialClientApplication) SetCacheAccessor(accessor CacheAccessor) {
	cca.clientApp.cacheAccessor = accessor
}

// CreateAuthCodeURL creates a URL used to acquire an authorization code
func (cca *ConfidentialClientApplication) CreateAuthCodeURL(authCodeURLParameters *AuthorizationCodeURLParameters) (string, error) {
	return cca.clientApp.createAuthCodeURL(authCodeURLParameters)
}

func (cca *ConfidentialClientApplication) AcquireTokenByAuthCode(
	authCodeParams *AcquireTokenAuthCodeParameters) (IAuthenticationResult, error) {
	return cca.clientApp.acquireTokenByAuthCode(authCodeParams)
}
