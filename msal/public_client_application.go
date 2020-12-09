// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"context"
	"net/http"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/cache"
)

// PublicClientApplicationOptions configures the PublicClientApplication's behavior.
type PublicClientApplicationOptions struct {
	// Accessor controls cache persistence.
	// By default there is no cache persistence.
	Accessor cache.ExportReplace

	// The host of the Azure Active Directory authority. The default is https://login.microsoftonline.com/common.
	Authority string

	// Client sets the transport for making HTTP requests.
	// Leave this as nil to use the default HTTP transport.
	HTTPClient HTTPClient
}

// DefaultPublicClientApplicationOptions returns an instance of PublicClientApplicationOptions initialized with default values.
func DefaultPublicClientApplicationOptions() PublicClientApplicationOptions {
	return PublicClientApplicationOptions{
		Authority:  authorityPublicCloud,
		HTTPClient: http.DefaultClient,
	}
}

// PublicClientApplication is a representation of public client applications.
// These are apps that run on devices or desktop computers or in a web browser and are not trusted to safely keep application secrets.
// For more information, visit https://docs.microsoft.com/azure/active-directory/develop/msal-client-applications.
type PublicClientApplication struct {
	clientApplication *clientApplication
}

// NewPublicClientApplication creates a PublicClientApplication instance given a client ID and authority URL.
// Pass nil for options to accept the default values; this is the same as passing the result
// from a call to DefaultPublicClientApplicationOptions().
func NewPublicClientApplication(clientID string, options *PublicClientApplicationOptions) (*PublicClientApplication, error) {
	if options == nil {
		def := DefaultPublicClientApplicationOptions()
		options = &def
	}
	clientApp, err := createClientApplication(options.HTTPClient, clientID, options.Authority)
	if err != nil {
		return nil, err
	}
	return &PublicClientApplication{
		clientApplication: clientApp,
	}, nil
}

// CreateAuthCodeURL creates a URL used to acquire an authorization code. Users need to call CreateAuthorizationCodeURLParameters and pass it in.
func (pca *PublicClientApplication) CreateAuthCodeURL(ctx context.Context, authCodeURLParameters AuthorizationCodeURLParameters) (string, error) {
	return pca.clientApplication.createAuthCodeURL(ctx, authCodeURLParameters)
}

// AcquireTokenSilent acquires a token from either the cache or using a refresh token
// Users need to create an AcquireTokenSilentParameters instance and pass it in.
func (pca *PublicClientApplication) AcquireTokenSilent(ctx context.Context, scopes []string, options *AcquireTokenSilentOptions) (msalbase.AuthenticationResult, error) {
	silentParameters := CreateAcquireTokenSilentParameters(scopes)
	silentParameters.requestType = requests.RefreshTokenPublic
	if options != nil {
		silentParameters.account = options.Account
	}
	return pca.clientApplication.acquireTokenSilent(ctx, silentParameters)
}

// AcquireTokenByUsernamePassword acquires a security token from the authority, via Username/Password Authentication.
// Users need to create an AcquireTokenUsernamePasswordParameters instance and pass it in.
// NOTE: this flow is NOT recommended.
func (pca *PublicClientApplication) AcquireTokenByUsernamePassword(ctx context.Context, scopes []string, username string, password string) (msalbase.AuthenticationResult, error) {
	authParams := pca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	usernamePasswordParameters := createAcquireTokenUsernamePasswordParameters(scopes, username, password)
	usernamePasswordParameters.augmentAuthenticationParameters(&authParams)

	req := requests.CreateUsernamePasswordRequest(pca.clientApplication.webRequestManager, authParams)
	return pca.clientApplication.executeTokenRequestWithCacheWrite(ctx, req, authParams)
}

// AcquireTokenByDeviceCode acquires a security token from the authority, by acquiring a device code and using that to acquire the token.
// Users need to create an AcquireTokenDeviceCodeParameters instance and pass it in.
func (pca *PublicClientApplication) AcquireTokenByDeviceCode(ctx context.Context, scopes []string, callback func(DeviceCodeResultProvider), options *AcquireTokenByDeviceCodeOptions) (msalbase.AuthenticationResult, error) {
	dcp := createAcquireTokenDeviceCodeParameters(ctx, scopes, callback)
	authParams := pca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	dcp.augmentAuthenticationParameters(&authParams)
	req := createDeviceCodeRequest(dcp.cancelCtx, pca.clientApplication.webRequestManager, authParams, dcp.deviceCodeCallback)
	return pca.clientApplication.executeTokenRequestWithCacheWrite(ctx, req, authParams)
}

// AcquireTokenByAuthCode is a request to acquire a security token from the authority, using an authorization code.
// Users need to create an AcquireTokenAuthCodeParameters instance and pass it in.
func (pca *PublicClientApplication) AcquireTokenByAuthCode(ctx context.Context, scopes []string, options *AcquireTokenByAuthCodeOptions) (msalbase.AuthenticationResult, error) {
	authCodeParams := createAcquireTokenAuthCodeParameters(scopes)
	authCodeParams.requestType = requests.AuthCodePublic
	if options != nil {
		authCodeParams.Code = options.Code
		authCodeParams.CodeChallenge = options.CodeChallenge
	}
	return pca.clientApplication.acquireTokenByAuthCode(ctx, authCodeParams)
}

// Accounts gets all the accounts in the token cache.
// If there are no accounts in the cache the returned slice is empty.
func (pca *PublicClientApplication) Accounts() []msalbase.Account {
	return pca.clientApplication.getAccounts()
}

// AcquireTokenByDeviceCodeOptions contains the optional parameters used to acquire an access token using the device code flow.
type AcquireTokenByDeviceCodeOptions struct {
	// placeholder for future optional args
}
