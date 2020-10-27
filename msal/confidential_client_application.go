// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
)

// ConfidentialClientApplication is a representation of confidential client applications.
// These are apps that run on servers (web apps, web API apps, or even service/daemon apps),
// and are capable of safely storing an application secret.
// For more information, visit https://docs.microsoft.com/azure/active-directory/develop/msal-client-applications
type ConfidentialClientApplication struct {
	clientApplication *clientApplication
	clientCredential  *msalbase.ClientCredential
}

// CreateConfidentialClientApplication creates a ConfidentialClientApplication instance given a client ID, authority URL and client credential.
func CreateConfidentialClientApplication(
	clientID string, authority string, clientCredential ClientCredentialProvider,
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

// This is used to convert the user-facing client credential interface to the internal representation of a client credential.
func createInternalClientCredential(interfaceCred ClientCredentialProvider) (*msalbase.ClientCredential, error) {
	if interfaceCred.GetCredentialType() == msalbase.ClientCredentialSecret {
		return msalbase.CreateClientCredentialFromSecret(interfaceCred.GetSecret())
	}
	if interfaceCred.GetAssertion().ClientCertificate != nil {
		return msalbase.CreateClientCredentialFromCertificateObject(
			interfaceCred.GetAssertion().ClientCertificate), nil
	}
	return msalbase.CreateClientCredentialFromAssertion(interfaceCred.GetAssertion().ClientAssertionJWT)
}

// SetHTTPManager allows users to use their own implementation of HTTPManager.
func (cca *ConfidentialClientApplication) SetHTTPManager(httpManager HTTPManager) {
	webRequestManager := createWebRequestManager(httpManager)
	cca.clientApplication.webRequestManager = webRequestManager
}

// SetCacheAccessor allows users to use an implementation of CacheAccessor to handle cache persistence.
func (cca *ConfidentialClientApplication) SetCacheAccessor(accessor CacheAccessor) {
	cca.clientApplication.cacheAccessor = accessor
}

// CreateAuthCodeURL creates a URL used to acquire an authorization code. Users need to call CreateAuthorizationCodeURLParameters and pass it in.
func (cca *ConfidentialClientApplication) CreateAuthCodeURL(authCodeURLParameters *AuthorizationCodeURLParameters) (string, error) {
	return cca.clientApplication.createAuthCodeURL(authCodeURLParameters)
}

// AcquireTokenSilent acquires a token from either the cache or using a refresh token
// Users need to create an AcquireTokenSilentParameters instance and pass it in.
func (cca *ConfidentialClientApplication) AcquireTokenSilent(
	silentParameters *AcquireTokenSilentParameters) (AuthenticationResultProvider, error) {
	silentParameters.requestType = requests.RefreshTokenConfidential
	silentParameters.clientCredential = cca.clientCredential
	return cca.clientApplication.acquireTokenSilent(silentParameters)
}

// AcquireTokenByAuthCode is a request to acquire a security token from the authority, using an authorization code.
// Users need to create an AcquireTokenAuthCodeParameters instance and pass it in.
func (cca *ConfidentialClientApplication) AcquireTokenByAuthCode(
	authCodeParams *AcquireTokenAuthCodeParameters) (AuthenticationResultProvider, error) {
	authCodeParams.requestType = requests.AuthCodeConfidential
	authCodeParams.clientCredential = cca.clientCredential
	return cca.clientApplication.acquireTokenByAuthCode(authCodeParams)
}

// AcquireTokenByClientCredential acquires a security token from the authority, using the client credentials grant.
// Users need to create an AcquireTokenClientCredentialParameters instance and pass it in.
func (cca *ConfidentialClientApplication) AcquireTokenByClientCredential(
	clientCredParams *AcquireTokenClientCredentialParameters) (AuthenticationResultProvider, error) {
	authParams := cca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	clientCredParams.augmentAuthenticationParameters(authParams)
	req := requests.CreateClientCredentialRequest(cca.clientApplication.webRequestManager, authParams, cca.clientCredential)
	return cca.clientApplication.executeTokenRequestWithCacheWrite(req, authParams)
}

// GetAccounts gets all the accounts in the token cache.
func (cca *ConfidentialClientApplication) GetAccounts() []AccountProvider {
	return cca.clientApplication.getAccounts()
}
