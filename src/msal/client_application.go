// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"errors"
	"reflect"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/tokencache"
	log "github.com/sirupsen/logrus"
)

type clientApplication struct {
	webRequestManager           requests.WebRequestManager
	clientApplicationParameters *clientApplicationParameters
	cacheContext                *CacheContext
	cacheAccessor               CacheAccessor
}

func createClientApplication(clientID string, authority string) *clientApplication {
	params := createClientApplicationParameters(clientID)
	params.SetAadAuthority(authority)
	httpManager := CreateHTTPManager()
	webRequestManager := createWebRequestManager(httpManager)
	storageManager := tokencache.CreateStorageManager()
	cacheManager := tokencache.CreateCacheManager(storageManager)
	cacheContext := &CacheContext{cacheManager}
	client := &clientApplication{
		webRequestManager:           webRequestManager,
		clientApplicationParameters: params,
		cacheContext:                cacheContext,
	}
	return client
}

func (client *clientApplication) createAuthCodeURL(authCodeURLParameters *AuthorizationCodeURLParameters) (string, error) {
	return authCodeURLParameters.CreateURL(client.webRequestManager, client.clientApplicationParameters.createAuthenticationParameters())
}

func (client *clientApplication) acquireTokenSilent(
	silentParameters *AcquireTokenSilentParameters) (AuthenticationResultInterfacer, error) {
	authParams := client.clientApplicationParameters.createAuthenticationParameters()
	silentParameters.augmentAuthenticationParameters(authParams)
	if client.cacheAccessor != nil {
		client.cacheAccessor.BeforeCacheAccess(client.cacheContext)
	}
	storageTokenResponse, err := client.cacheContext.cache.TryReadCache(authParams, client.webRequestManager)
	if client.cacheAccessor != nil {
		client.cacheAccessor.AfterCacheAccess(client.cacheContext)
	}
	if err != nil {
		return nil, err
	}
	if storageTokenResponse != nil {
		result, err := msalbase.CreateAuthenticationResultFromStorageTokenResponse(storageTokenResponse)
		if err != nil {
			log.Error(err)
			if reflect.ValueOf(storageTokenResponse.RefreshToken).IsNil() {
				return nil, errors.New("no refresh token found")
			}
			req := requests.CreateRefreshTokenExchangeRequest(client.webRequestManager,
				authParams, storageTokenResponse.RefreshToken)
			return client.executeTokenRequestWithCacheWrite(req, authParams)
		}
		return result, nil
	}
	if reflect.ValueOf(storageTokenResponse.RefreshToken).IsNil() {
		return nil, errors.New("no refresh token found")
	}
	req := requests.CreateRefreshTokenExchangeRequest(client.webRequestManager,
		authParams, storageTokenResponse.RefreshToken)
	return client.executeTokenRequestWithCacheWrite(req, authParams)
}

func (client *clientApplication) acquireTokenByAuthCode(
	authCodeParams *AcquireTokenAuthCodeParameters) (AuthenticationResultInterfacer, error) {
	authParams := client.clientApplicationParameters.createAuthenticationParameters()
	authCodeParams.augmentAuthenticationParameters(authParams)
	req := requests.CreateAuthCodeRequest(client.webRequestManager, authParams, authCodeParams.requestType)
	req.Code = authCodeParams.Code
	req.CodeChallenge = authCodeParams.codeChallenge
	if req.RequestType == requests.AuthCodeClientSecret {
		req.ClientSecret = authCodeParams.clientSecret
	}
	if req.RequestType == requests.AuthCodeClientAssertion {
		req.ClientAssertion = authCodeParams.clientAssertion
	}
	return client.executeTokenRequestWithCacheWrite(req, authParams)
}

func (client *clientApplication) executeTokenRequestWithoutCacheWrite(
	req requests.TokenRequester,
	authParams *msalbase.AuthParametersInternal) (AuthenticationResultInterfacer, error) {
	tokenResponse, err := req.Execute()
	if err != nil {
		return nil, err
	}
	return msalbase.CreateAuthenticationResult(tokenResponse, nil)
}

func (client *clientApplication) executeTokenRequestWithCacheWrite(
	req requests.TokenRequester,
	authParams *msalbase.AuthParametersInternal) (AuthenticationResultInterfacer, error) {
	tokenResponse, err := req.Execute()
	if err != nil {
		return nil, err
	}
	if client.cacheAccessor != nil {
		client.cacheAccessor.BeforeCacheAccess(client.cacheContext)
		defer client.cacheAccessor.AfterCacheAccess(client.cacheContext)
	}
	account, err := client.cacheContext.cache.CacheTokenResponse(authParams, tokenResponse)
	if err != nil {
		return nil, err
	}
	return msalbase.CreateAuthenticationResult(tokenResponse, account)
}

func (client *clientApplication) getAccounts() []AccountInterfacer {
	returnedAccounts := []AccountInterfacer{}
	if client.cacheAccessor != nil {
		client.cacheAccessor.BeforeCacheAccess(client.cacheContext)
	}
	accounts := client.cacheContext.cache.GetAllAccounts()
	if client.cacheAccessor != nil {
		client.cacheAccessor.AfterCacheAccess(client.cacheContext)
	}
	for _, acc := range accounts {
		returnedAccounts = append(returnedAccounts, acc)
	}
	return returnedAccounts
}
