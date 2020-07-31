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

type ConfidentialClientApplication struct {
	clientApplication *clientApplication
	clientSecret      string
	clientAssertion   *msalbase.ClientAssertion
	clientType        confidentialClientType
}

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
	if cca.clientType == confidentialClientSecret {
		authCodeParams.RequestType = requests.AuthCodeClientSecret
		authCodeParams.ClientSecret = cca.clientSecret
	} else if cca.clientType == confidentialClientAssertion {
		authCodeParams.RequestType = requests.AuthCodeClientAssertion
		authCodeParams.ClientAssertion = cca.clientAssertion
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
		cca.clientApplication.webRequestManager, authParams, cca.clientSecret)
	return cca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

func (cca *ConfidentialClientApplication) AcquireTokenByClientAssertion(
	clientParams *AcquireTokenClientAssertionParameters) (IAuthenticationResult, error) {
	authParams := cca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	clientParams.augmentAuthenticationParameters(authParams)
	req := requests.CreateClientAssertionRequest(
		cca.clientApplication.webRequestManager, authParams, cca.clientAssertion,
	)
	return cca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

func (cca *ConfidentialClientApplication) GetAccounts() []IAccount {
	return cca.clientApplication.getAccounts()
}
