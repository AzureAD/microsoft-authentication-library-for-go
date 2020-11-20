// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"context"
	"errors"
	"reflect"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/tokencache"
	log "github.com/sirupsen/logrus"
)

type noopCacheAccessor struct{}

func (n noopCacheAccessor) BeforeCacheAccess(context *CacheContext) {}
func (n noopCacheAccessor) AfterCacheAccess(context *CacheContext)  {}

type clientApplication struct {
	webRequestManager           requests.WebRequestManager
	clientApplicationParameters *clientApplicationParameters
	cacheContext                *CacheContext
	cacheAccessor               CacheAccessor
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
		cacheContext: &CacheContext{
			cache: tokencache.CreateCacheManager(
				tokencache.CreateStorageManager(),
			),
		},
	}, nil
}

func (client *clientApplication) createAuthCodeURL(ctx context.Context, authCodeURLParameters AuthorizationCodeURLParameters) (string, error) {
	return authCodeURLParameters.createURL(ctx, client.webRequestManager, client.clientApplicationParameters.createAuthenticationParameters())
}

func (client *clientApplication) acquireTokenSilent(ctx context.Context, silent AcquireTokenSilentParameters) (msalbase.AuthenticationResult, error) {
	authParams := client.clientApplicationParameters.createAuthenticationParameters()
	silent.augmentAuthenticationParameters(&authParams)

	// TODO(jdoak/msal): This accessor stuff should be integrated into the
	// CacheManager instead of here probably by passing the accessor in its
	// constructor and defining these methods.
	client.cacheAccessor.BeforeCacheAccess(client.cacheContext)
	defer client.cacheAccessor.AfterCacheAccess(client.cacheContext)
	storageTokenResponse, err := client.cacheContext.cache.TryReadCache(ctx, authParams, client.webRequestManager)
	if err != nil {
		return msalbase.AuthenticationResult{}, err
	}

	result, err := msalbase.CreateAuthenticationResultFromStorageTokenResponse(storageTokenResponse)
	if err != nil {
		log.Error(err)
		if reflect.ValueOf(storageTokenResponse.RefreshToken).IsNil() {
			return msalbase.AuthenticationResult{}, errors.New("no refresh token found")
		}
		req := requests.CreateRefreshTokenExchangeRequest(client.webRequestManager,
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

	client.cacheAccessor.BeforeCacheAccess(client.cacheContext)
	defer client.cacheAccessor.AfterCacheAccess(client.cacheContext)
	account, err := client.cacheContext.cache.CacheTokenResponse(authParams, tokenResponse)
	if err != nil {
		return msalbase.AuthenticationResult{}, err
	}
	return msalbase.CreateAuthenticationResult(tokenResponse, account)
}

func (client *clientApplication) getAccounts() []msalbase.Account {
	client.cacheAccessor.BeforeCacheAccess(client.cacheContext)
	defer client.cacheAccessor.AfterCacheAccess(client.cacheContext)
	accounts, err := client.cacheContext.cache.GetAllAccounts()
	if err != nil {
		return nil
	}
	return accounts
}
