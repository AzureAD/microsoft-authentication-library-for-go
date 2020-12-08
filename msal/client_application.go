// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"context"
	"errors"
	"reflect"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/storage"
	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/cache"
)

type noopCacheAccessor struct{}

func (n noopCacheAccessor) IntoCache(cache cache.Unmarshaler)      {}
func (n noopCacheAccessor) AfterCacheAccess(cache cache.Marshaler) {}

// managet provides an internal cache. It is defined to allow faking the cache in tests.
// In all production use it is a *storage.Manager.
type manager interface {
	Read(ctx context.Context, authParameters msalbase.AuthParametersInternal, webRequestManager requests.WebRequestManager) (msalbase.StorageTokenResponse, error)
	Write(authParameters msalbase.AuthParametersInternal, tokenResponse msalbase.TokenResponse) (msalbase.Account, error)
	GetAllAccounts() ([]msalbase.Account, error)
}

type clientApplication struct {
	webRequestManager           requests.WebRequestManager
	clientApplicationParameters *clientApplicationParameters
	manager                     manager // *storage.Manager or fakeManager in tests
	cacheAccessor               cache.Token
}

func createClientApplication(httpClient HTTPClient, clientID string, authority string) (*clientApplication, error) {
	params, err := createClientApplicationParameters(clientID, authority)
	if err != nil {
		return nil, err
	}

	return &clientApplication{
		webRequestManager:           createWebRequestManager(httpClient),
		clientApplicationParameters: params,
		cacheAccessor:               noopCacheAccessor{},
		manager:                     storage.New(),
	}, nil
}

func (client *clientApplication) createAuthCodeURL(ctx context.Context, authCodeURLParameters AuthorizationCodeURLParameters) (string, error) {
	return authCodeURLParameters.createURL(ctx, client.webRequestManager, client.clientApplicationParameters.createAuthenticationParameters())
}

func (client *clientApplication) acquireTokenSilent(ctx context.Context, silent AcquireTokenSilentParameters) (msalbase.AuthenticationResult, error) {
	authParams := client.clientApplicationParameters.createAuthenticationParameters()
	silent.augmentAuthenticationParameters(&authParams)

	// TODO(jdoak): Think about removing this after refactor.
	if sm, ok := client.manager.(*storage.Manager); ok {
		client.cacheAccessor.IntoCache(sm)
		defer client.cacheAccessor.AfterCacheAccess(sm)
	}

	storageTokenResponse, err := client.manager.Read(ctx, authParams, client.webRequestManager)
	if err != nil {
		return msalbase.AuthenticationResult{}, err
	}

	result, err := msalbase.CreateAuthenticationResultFromStorageTokenResponse(storageTokenResponse)
	if err != nil {
		if reflect.ValueOf(storageTokenResponse.RefreshToken).IsNil() {
			return msalbase.AuthenticationResult{}, errors.New("no refresh token found")
		}
		req := requests.NewRefreshTokenExchangeRequest(client.webRequestManager,
			authParams, storageTokenResponse.RefreshToken, silent.requestType)
		if req.RequestType == requests.RefreshTokenConfidential {
			req.ClientCredential = silent.clientCredential
		}
		return client.executeTokenRequestWithCacheWrite(ctx, req, authParams)
	}
	return result, nil
}

func (client *clientApplication) acquireTokenByAuthCode(ctx context.Context, authCodeParams *acquireTokenAuthCodeParameters) (msalbase.AuthenticationResult, error) {
	authParams := client.clientApplicationParameters.createAuthenticationParameters()
	authCodeParams.augmentAuthenticationParameters(&authParams)
	req := requests.CreateAuthCodeRequest(client.webRequestManager, authParams, authCodeParams.requestType)
	req.Code = authCodeParams.Code
	req.CodeChallenge = authCodeParams.CodeChallenge
	if req.RequestType == requests.AuthCodeConfidential {
		req.ClientCredential = authCodeParams.clientCredential
	}
	return client.executeTokenRequestWithCacheWrite(ctx, req, authParams)
}

func (client *clientApplication) executeTokenRequestWithoutCacheWrite(ctx context.Context, req requests.TokenRequester, authParams msalbase.AuthParametersInternal) (AuthenticationResultProvider, error) {
	tokenResponse, err := req.Execute(ctx)
	if err != nil {
		return nil, err
	}
	// TODO(msal expert): This used to pass nil for Account. I'm not sure if that
	// was really valid or not or had hidden bugs (like the GetAccount() call). This
	// is safe from a Go standpoint, but I'm not sure that MSAL doesn't acutally depend
	// on Account here.  If this is ok, I'll just add a bit of documentation here.
	return msalbase.CreateAuthenticationResult(tokenResponse, msalbase.Account{})
}

func (client *clientApplication) executeTokenRequestWithCacheWrite(ctx context.Context, req requests.TokenRequester, authParams msalbase.AuthParametersInternal) (msalbase.AuthenticationResult, error) {
	tokenResponse, err := req.Execute(ctx)
	if err != nil {
		return msalbase.AuthenticationResult{}, err
	}

	// TODO(jdoak): Think about removing this after refactor.
	if sm, ok := client.manager.(*storage.Manager); ok {
		client.cacheAccessor.IntoCache(sm)
		defer client.cacheAccessor.AfterCacheAccess(sm)
	}

	account, err := client.manager.Write(authParams, tokenResponse)
	if err != nil {
		return msalbase.AuthenticationResult{}, err
	}
	return msalbase.CreateAuthenticationResult(tokenResponse, account)
}

func (client *clientApplication) getAccounts() []msalbase.Account {
	// TODO(jdoak): Think about removing this after refactor.
	if sm, ok := client.manager.(*storage.Manager); ok {
		client.cacheAccessor.IntoCache(sm)
		defer client.cacheAccessor.AfterCacheAccess(sm)
	}

	accounts, err := client.manager.GetAllAccounts()
	if err != nil {
		return nil
	}
	return accounts
}
