// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"context"
	"net/http"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
)

// ConfidentialClientApplicationOptions configures the PublicClientApplication's behavior.
type ConfidentialClientApplicationOptions struct {
	// Accessor controls cache persistence.
	// By default there is no cache persistence.
	Accessor CacheAccessor

	// The host of the Azure Active Directory authority. The default is https://login.microsoftonline.com/common.
	Authority string

	// Client sets the transport for making HTTP requests.
	// Leave this as nil to use the default HTTP transport.
	HTTPClient HTTPClient
}

// DefaultConfidentialClientApplicationOptions returns an instance of ConfidentialClientApplicationOptions initialized with default values.
func DefaultConfidentialClientApplicationOptions() ConfidentialClientApplicationOptions {
	return ConfidentialClientApplicationOptions{
		Authority:  authorityPublicCloud,
		HTTPClient: http.DefaultClient,
	}
}

// ConfidentialClientApplication is a representation of confidential client applications.
// These are apps that run on servers (web apps, web API apps, or even service/daemon apps),
// and are capable of safely storing an application secret.
// For more information, visit https://docs.microsoft.com/azure/active-directory/develop/msal-client-applications
type ConfidentialClientApplication struct {
	clientApplication *clientApplication
	clientCredential  msalbase.ClientCredential
}

// NewConfidentialClientApplication creates a ConfidentialClientApplication instance given a client ID, authority URL and client credential.
// Pass nil for options to accept the default values; this is the same as passing the result
// from a call to DefaultConfidentialClientApplicationOptions().
func NewConfidentialClientApplication(clientID string, clientCredential ClientCredentialProvider, options *ConfidentialClientApplicationOptions) (*ConfidentialClientApplication, error) {
	cred, err := createInternalClientCredential(clientCredential)
	if err != nil {
		return nil, err
	}
	if options == nil {
		def := DefaultConfidentialClientApplicationOptions()
		options = &def
	}
	clientApp, err := createClientApplication(options.HTTPClient, clientID, options.Authority)
	if err != nil {
		return nil, err
	}
	return &ConfidentialClientApplication{
		clientApplication: clientApp,
		clientCredential:  cred,
	}, nil
}

// This is used to convert the user-facing client credential interface to the internal representation of a client credential
func createInternalClientCredential(interfaceCred ClientCredentialProvider) (msalbase.ClientCredential, error) {
	if interfaceCred.GetCredentialType() == msalbase.ClientCredentialSecret {
		return msalbase.CreateClientCredentialFromSecret(interfaceCred.GetSecret())

	}
	if interfaceCred.GetAssertion().ClientCertificate != nil {
		return msalbase.CreateClientCredentialFromCertificateObject(
			interfaceCred.GetAssertion().ClientCertificate), nil
	}
	return msalbase.CreateClientCredentialFromAssertion(interfaceCred.GetAssertion().ClientAssertionJWT)
}

// CreateAuthCodeURL creates a URL used to acquire an authorization code. Users need to call CreateAuthorizationCodeURLParameters and pass it in.
func (cca *ConfidentialClientApplication) CreateAuthCodeURL(ctx context.Context, authCodeURLParameters AuthorizationCodeURLParameters) (string, error) {
	return cca.clientApplication.createAuthCodeURL(ctx, authCodeURLParameters)
}

// AcquireTokenSilent acquires a token from either the cache or using a refresh token
// Users need to create an AcquireTokenSilentParameters instance and pass it in.
func (cca *ConfidentialClientApplication) AcquireTokenSilent(ctx context.Context, scopes []string, options *AcquireTokenSilentOptions) (msalbase.AuthenticationResult, error) {
	silentParameters := CreateAcquireTokenSilentParameters(scopes)
	silentParameters.requestType = requests.RefreshTokenConfidential
	silentParameters.clientCredential = cca.clientCredential
	if options != nil {
		silentParameters.account = options.Account
	}
	return cca.clientApplication.acquireTokenSilent(ctx, silentParameters)
}

// AcquireTokenByAuthCode is a request to acquire a security token from the authority, using an authorization code.
// Users need to create an AcquireTokenAuthCodeParameters instance and pass it in.
func (cca *ConfidentialClientApplication) AcquireTokenByAuthCode(ctx context.Context, scopes []string, options *AcquireTokenByAuthCodeOptions) (msalbase.AuthenticationResult, error) {
	authCodeParams := createAcquireTokenAuthCodeParameters(scopes)
	authCodeParams.requestType = requests.AuthCodeConfidential
	authCodeParams.clientCredential = cca.clientCredential
	if options != nil {
		authCodeParams.Code = options.Code
		authCodeParams.CodeChallenge = options.CodeChallenge
		authCodeParams.RedirectURI = options.RedirectURI
	}
	return cca.clientApplication.acquireTokenByAuthCode(ctx, authCodeParams)

}

// AcquireTokenByClientCredential acquires a security token from the authority, using the client credentials grant.
// Users need to create an AcquireTokenClientCredentialParameters instance and pass it in.
func (cca *ConfidentialClientApplication) AcquireTokenByClientCredential(ctx context.Context, scopes []string) (msalbase.AuthenticationResult, error) {
	authParams := cca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	clientCredParams := createAcquireTokenClientCredentialParameters(scopes)
	clientCredParams.augmentAuthenticationParameters(&authParams)

	req := requests.CreateClientCredentialRequest(cca.clientApplication.webRequestManager, authParams, cca.clientCredential)
	return cca.clientApplication.executeTokenRequestWithCacheWrite(ctx, req, authParams)
}

// Accounts gets all the accounts in the token cache.
func (cca *ConfidentialClientApplication) Accounts() []msalbase.Account {
	return cca.clientApplication.getAccounts()
}
