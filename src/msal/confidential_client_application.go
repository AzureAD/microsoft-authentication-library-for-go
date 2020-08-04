// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"errors"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
)

type ConfidentialClientApplication struct {
	clientApplication *clientApplication
	clientCredential  *ClientCredential
}

func CreateConfidentialClientApplication(
	clientID string, authority string, clientCredential *ClientCredential,
) *ConfidentialClientApplication {
	clientApp := createClientApplication(clientID, authority)
	return &ConfidentialClientApplication{
		clientApplication: clientApp,
		clientCredential:  clientCredential,
	}
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
	if cca.clientCredential.credentialType == clientSecret {
		authCodeParams.requestType = requests.AuthCodeClientSecret
		authCodeParams.clientSecret = cca.clientCredential.clientSecret
	} else if cca.clientCredential.credentialType == clientAssertion {
		authCodeParams.requestType = requests.AuthCodeClientAssertion
		authCodeParams.clientAssertion = cca.clientCredential.clientAssertion
	} else {
		return nil, errors.New("need client secret or assertion")
	}
	return cca.clientApplication.acquireTokenByAuthCode(authCodeParams)

}

func (cca *ConfidentialClientApplication) AcquireTokenByClientSecret(
	clientCredParams *AcquireTokenClientSecretParameters) (IAuthenticationResult, error) {
	authParams := cca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	clientCredParams.augmentAuthenticationParameters(authParams)
	req := requests.CreateClientSecretRequest(
		cca.clientApplication.webRequestManager, authParams, cca.clientCredential.clientSecret)
	return cca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

func (cca *ConfidentialClientApplication) AcquireTokenByClientAssertion(
	clientParams *AcquireTokenClientAssertionParameters) (IAuthenticationResult, error) {
	authParams := cca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	clientParams.augmentAuthenticationParameters(authParams)
	req := requests.CreateClientAssertionRequest(
		cca.clientApplication.webRequestManager, authParams, cca.clientCredential.clientAssertion,
	)
	return cca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

func (cca *ConfidentialClientApplication) GetAccounts() []IAccount {
	return cca.clientApplication.getAccounts()
}
