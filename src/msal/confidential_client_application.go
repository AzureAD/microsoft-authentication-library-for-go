// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
)

type ConfidentialClientApplication struct {
	clientApplication *clientApplication
	clientCredential  *msalbase.ClientCredential
}

func CreateConfidentialClientApplication(
	clientID string, authority string, clientCredential ClientCredentialInterfacer,
) (*ConfidentialClientApplication, error) {
	cred, err := createInternalClientCredential(clientCredential)
	if err != nil {
		return nil, err
	}
	clientApp := createClientApplication(clientID, authority)
	return &ConfidentialClientApplication{
		clientApplication: clientApp,
		clientCredential:  cred,
	}, nil
}

func createInternalClientCredential(interfaceCred ClientCredentialInterfacer) (*msalbase.ClientCredential, error) {
	if interfaceCred.GetCredentialType() == msalbase.ClientCredentialSecret {
		return msalbase.CreateClientCredentialFromSecret(interfaceCred.GetSecret())

	}
	if interfaceCred.GetAssertion().ClientCertificate != nil {
		return msalbase.CreateClientCredentialFromCertificateObject(
			interfaceCred.GetAssertion().ClientCertificate), nil
	}
	return msalbase.CreateClientCredentialFromAssertion(interfaceCred.GetAssertion().ClientAssertionJWT)
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
	silentParameters.requestType = requests.RefreshTokenConfidential
	silentParameters.clientCredential = cca.clientCredential
	return cca.clientApplication.acquireTokenSilent(silentParameters)
}

func (cca *ConfidentialClientApplication) AcquireTokenByAuthCode(
	authCodeParams *AcquireTokenAuthCodeParameters) (IAuthenticationResult, error) {
	authCodeParams.requestType = requests.AuthCodeConfidential
	authCodeParams.clientCredential = cca.clientCredential
	return cca.clientApplication.acquireTokenByAuthCode(authCodeParams)

}

func (cca *ConfidentialClientApplication) AcquireTokenByClientCredential(
	clientCredParams *AcquireTokenClientCredentialParameters) (IAuthenticationResult, error) {
	authParams := cca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	clientCredParams.augmentAuthenticationParameters(authParams)
	req := requests.CreateClientCredentialRequest(cca.clientApplication.webRequestManager, authParams, cca.clientCredential)
	return cca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

func (cca *ConfidentialClientApplication) GetAccounts() []IAccount {
	return cca.clientApplication.getAccounts()
}
