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

//SetHTTPManager allows users to use their own implementation of HTTPManager
func (cca *ConfidentialClientApplication) SetHTTPManager(httpManager HTTPManager) {
	webRequestManager := createWebRequestManager(httpManager)
	cca.clientApplication.webRequestManager = webRequestManager
}

//SetCacheAccessor allows users to use an implementation of CacheAccessor to handle cache persistence
func (cca *ConfidentialClientApplication) SetCacheAccessor(accessor CacheAccessor) {
	cca.clientApplication.cacheAccessor = accessor
}

// CreateAuthCodeURL creates a URL used to acquire an authorization code
func (cca *ConfidentialClientApplication) CreateAuthCodeURL(authCodeURLParameters *AuthorizationCodeURLParameters) (string, error) {
	return cca.clientApplication.createAuthCodeURL(authCodeURLParameters)
}

//AcquireTokenSilent acquires a token from either the cache or using a refresh token
func (cca *ConfidentialClientApplication) AcquireTokenSilent(
	silentParameters *AcquireTokenSilentParameters) (AuthenticationResultInterfacer, error) {
	return cca.clientApplication.acquireTokenSilent(silentParameters)
}

//AcquireTokenByAuthCode acquires a security token from the authority, using an authorization code
func (cca *ConfidentialClientApplication) AcquireTokenByAuthCode(
	authCodeParams *AcquireTokenAuthCodeParameters) (AuthenticationResultInterfacer, error) {
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

//AcquireTokenByClientSecret acquires a security token from the authority using a client secret
func (cca *ConfidentialClientApplication) AcquireTokenByClientSecret(
	clientCredParams *AcquireTokenClientSecretParameters) (AuthenticationResultInterfacer, error) {
	authParams := cca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	clientCredParams.augmentAuthenticationParameters(authParams)
	req := requests.CreateClientSecretRequest(
		cca.clientApplication.webRequestManager, authParams, cca.clientCredential.clientSecret)
	return cca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

//AcquireTokenByClientAssertion acquires a security token from the authority using a assertion, which can be either a JWT or certificate
func (cca *ConfidentialClientApplication) AcquireTokenByClientAssertion(
	clientParams *AcquireTokenClientAssertionParameters) (AuthenticationResultInterfacer, error) {
	authParams := cca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	clientParams.augmentAuthenticationParameters(authParams)
	req := requests.CreateClientAssertionRequest(
		cca.clientApplication.webRequestManager, authParams, cca.clientCredential.clientAssertion,
	)
	return cca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

//GetAccounts gets all the accounts in the cache
func (cca *ConfidentialClientApplication) GetAccounts() []AccountInterfacer {
	return cca.clientApplication.getAccounts()
}
