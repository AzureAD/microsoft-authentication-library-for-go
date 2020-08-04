// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"errors"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
)

type confidentialClientType int

const (
	confidentialClientSecret confidentialClientType = iota
	confidentialClientAssertion
)

//ConfidentialClientApplication is the struct used to acquire tokens for confidential client apps
type ConfidentialClientApplication struct {
	clientApplication *clientApplication
	clientSecret      string
	clientAssertion   *msalbase.ClientAssertion
	clientType        confidentialClientType
}

//CreateConfidentialClientApplicationFromSecret creates a ConfidentialClientApplication with a client secret
func CreateConfidentialClientApplicationFromSecret(
	clientID string, authority string, clientSecret string) *ConfidentialClientApplication {
	clientApp := createClientApplication(clientID, authority)
	cca := &ConfidentialClientApplication{
		clientApplication: clientApp,
		clientSecret:      clientSecret,
		clientType:        confidentialClientSecret,
	}
	return cca
}

//CreateConfidentialClientApplicationFromCertificate creates a ConfidentialClientApplication with a certificate (private key and thumbprint)
func CreateConfidentialClientApplicationFromCertificate(
	clientID string, authority string, thumbprint string, key []byte) *ConfidentialClientApplication {
	clientApp := createClientApplication(clientID, authority)
	cca := &ConfidentialClientApplication{
		clientApplication: clientApp,
		clientAssertion:   msalbase.CreateClientAssertionFromCertificate(thumbprint, key),
		clientType:        confidentialClientAssertion,
	}
	return cca
}

//CreateConfidentialClientApplicationFromAssertion creates a ConfidentialClientApplication with an assertion string
func CreateConfidentialClientApplicationFromAssertion(
	clientID string, authority string, assertion string) *ConfidentialClientApplication {
	clientApp := createClientApplication(clientID, authority)
	cca := &ConfidentialClientApplication{
		clientApplication: clientApp,
		clientAssertion:   msalbase.CreateClientAssertionFromJWT(assertion),
		clientType:        confidentialClientAssertion,
	}
	return cca
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
	if cca.clientType == confidentialClientSecret {
		authCodeParams.RequestType = requests.AuthCodeClientSecret
		authCodeParams.ClientSecret = cca.clientSecret
	} else if cca.clientType == confidentialClientAssertion {
		authCodeParams.RequestType = requests.AuthCodeClientAssertion
		authCodeParams.ClientAssertion = cca.clientAssertion
	} else {
		return nil, errors.New("Need client secret or assertion")
	}
	return cca.clientApplication.acquireTokenByAuthCode(authCodeParams)

}

//AcquireTokenByClientSecret acquires a security token from the authority using a client secret
func (cca *ConfidentialClientApplication) AcquireTokenByClientSecret(
	clientCredParams *AcquireTokenClientSecretParameters) (AuthenticationResultInterfacer, error) {
	authParams := cca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	clientCredParams.augmentAuthenticationParameters(authParams)
	req := requests.CreateClientSecretRequest(
		cca.clientApplication.webRequestManager, authParams, cca.clientSecret)
	return cca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

//AcquireTokenByClientAssertion acquires a security token from the authority using a assertion, which can be either a JWT or certificate
func (cca *ConfidentialClientApplication) AcquireTokenByClientAssertion(
	clientParams *AcquireTokenClientAssertionParameters) (AuthenticationResultInterfacer, error) {
	authParams := cca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	clientParams.augmentAuthenticationParameters(authParams)
	req := requests.CreateClientAssertionRequest(
		cca.clientApplication.webRequestManager, authParams, cca.clientAssertion,
	)
	return cca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

//GetAccounts gets all the accounts in the cache
func (cca *ConfidentialClientApplication) GetAccounts() []AccountInterfacer {
	return cca.clientApplication.getAccounts()
}
