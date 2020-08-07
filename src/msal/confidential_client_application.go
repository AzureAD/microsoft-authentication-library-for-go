// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
)

//ConfidentialClientApplication is used to acquire tokens in applications that run on servers
//They can be trusted to keep secrets
type ConfidentialClientApplication struct {
	clientApplication *clientApplication
	clientCredential  *msalbase.ClientCredential
}

//CreateConfidentialClientApplication creates a ConfidentialClientApplication instance given a client ID, authority and client credential
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

//This is used to convert the user-facing client credential interface to the internal representation of a client credential
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
	silentParameters.requestType = requests.RefreshTokenConfidential
	silentParameters.clientCredential = cca.clientCredential
	return cca.clientApplication.acquireTokenSilent(silentParameters)
}

//AcquireTokenByAuthCode acquires a security token from the authority, using an authorization code
func (cca *ConfidentialClientApplication) AcquireTokenByAuthCode(
	authCodeParams *AcquireTokenAuthCodeParameters) (AuthenticationResultInterfacer, error) {
	authCodeParams.requestType = requests.AuthCodeConfidential
	authCodeParams.clientCredential = cca.clientCredential
	return cca.clientApplication.acquireTokenByAuthCode(authCodeParams)

}

//AcquireTokenByClientCredential acquires a security token from the authority, using the client credentials grant
func (cca *ConfidentialClientApplication) AcquireTokenByClientCredential(
	clientCredParams *AcquireTokenClientCredentialParameters) (AuthenticationResultInterfacer, error) {
	authParams := cca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	clientCredParams.augmentAuthenticationParameters(authParams)
	req := requests.CreateClientCredentialRequest(cca.clientApplication.webRequestManager, authParams, cca.clientCredential)
	return cca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

//GetAccounts gets all the accounts in the cache
func (cca *ConfidentialClientApplication) GetAccounts() []AccountInterfacer {
	return cca.clientApplication.getAccounts()
}
