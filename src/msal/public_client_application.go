// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/tokencache"
)

// PublicClientApplication is used to acquire tokens in desktop or mobile applications (Desktop / UWP / Xamarin.iOS / Xamarin.Android).
// public client applications are not trusted to safely keep application secrets, and therefore they only access Web APIs in the name of the user only
// (they only support public client flows). For details see https://aka.ms/msal-net-client-applications
type PublicClientApplication struct {
	pcaParameters     *PublicClientApplicationParameters
	webRequestManager requests.IWebRequestManager
	cacheContext      *CacheContext
	cacheAccessor     CacheAccessor
}

// CreatePublicClientApplication creates a PublicClientApplication Instance given its parameters, which include client ID and authority info
func CreatePublicClientApplication(pcaParameters *PublicClientApplicationParameters) (*PublicClientApplication, error) {
	err := pcaParameters.validate()
	if err != nil {
		return nil, err
	}

	httpManager := CreateHTTPManager()
	webRequestManager := CreateWebRequestManager(httpManager)

	// todo: check parameters for whether persistent cache is desired, or self-caching (callback to byte array read/write)
	storageManager := tokencache.CreateStorageManager()
	cacheManager := tokencache.CreateCacheManager(storageManager)
	cacheContext := &CacheContext{cacheManager}

	pca := &PublicClientApplication{
		pcaParameters:     pcaParameters,
		webRequestManager: webRequestManager,
		cacheContext:      cacheContext,
	}
	return pca, nil
}

func (pca *PublicClientApplication) SetHTTPManager(httpManager IHTTPManager) {
	webRequestManager := CreateWebRequestManager(httpManager)
	pca.webRequestManager = webRequestManager
}

func (pca *PublicClientApplication) SetCacheAccessor(accessor CacheAccessor) {
	pca.cacheAccessor = accessor
}

// CreateAuthCodeURL creates a URL used to acquire an authorization code
func (pca *PublicClientApplication) CreateAuthCodeURL(authCodeURLParameters *AuthorizationCodeURLParameters) (string, error) {
	return authCodeURLParameters.CreateURL(pca.webRequestManager, pca.pcaParameters.createAuthenticationParameters())
}

// AcquireTokenSilent stuff
func (pca *PublicClientApplication) AcquireTokenSilent(
	silentParameters *AcquireTokenSilentParameters) (IAuthenticationResult, error) {
	authParams := pca.pcaParameters.createAuthenticationParameters()
	silentParameters.augmentAuthenticationParameters(authParams)
	if pca.cacheAccessor != nil {
		pca.cacheAccessor.BeforeCacheAccess(pca.cacheContext)
	}
	storageTokenResponse, err := pca.cacheContext.cache.TryReadCache(authParams, pca.webRequestManager)
	if pca.cacheAccessor != nil {
		pca.cacheAccessor.AfterCacheAccess(pca.cacheContext)
	}
	if err != nil {
		return nil, err
	}
	if storageTokenResponse != nil {
		result, err := msalbase.CreateAuthenticationResultFromStorageTokenResponse(storageTokenResponse)
		if err == nil {
			return result, err
		}
		req := requests.CreateRefreshTokenExchangeRequest(pca.webRequestManager, authParams, storageTokenResponse.RefreshToken)
		return pca.executeTokenRequestWithCacheWrite(req, authParams)
	}

	req := requests.CreateRefreshTokenExchangeRequest(pca.webRequestManager, authParams, storageTokenResponse.RefreshToken)
	return pca.executeTokenRequestWithCacheWrite(req, authParams)
}

// AcquireTokenByUsernamePassword is a non-interactive request to acquire a security token from the authority, via Username/Password Authentication.
func (pca *PublicClientApplication) AcquireTokenByUsernamePassword(
	usernamePasswordParameters *AcquireTokenUsernamePasswordParameters) (IAuthenticationResult, error) {
	authParams := pca.pcaParameters.createAuthenticationParameters()
	usernamePasswordParameters.augmentAuthenticationParameters(authParams)
	req := requests.CreateUsernamePasswordRequest(pca.webRequestManager, authParams)
	return pca.executeTokenRequestWithCacheWrite(req, authParams)
}

// AcquireTokenByDeviceCode stuff
func (pca *PublicClientApplication) AcquireTokenByDeviceCode(
	deviceCodeParameters *AcquireTokenDeviceCodeParameters) (IAuthenticationResult, error) {
	authParams := pca.pcaParameters.createAuthenticationParameters()
	deviceCodeParameters.augmentAuthenticationParameters(authParams)
	req := createDeviceCodeRequest(deviceCodeParameters.cancelCtx, pca.webRequestManager, authParams, deviceCodeParameters.deviceCodeCallback)
	return pca.executeTokenRequestWithCacheWrite(req, authParams)
}

// AcquireTokenByAuthCode is a request to acquire a security token from the authority, using an authorization code
func (pca *PublicClientApplication) AcquireTokenByAuthCode(
	authCodeParams *AcquireTokenAuthCodeParameters) (IAuthenticationResult, error) {
	authParams := pca.pcaParameters.createAuthenticationParameters()
	authCodeParams.augmentAuthenticationParameters(authParams)
	req := requests.CreateAuthCodeRequest(pca.webRequestManager, authParams)
	req.Code = authCodeParams.Code
	req.CodeChallenge = authCodeParams.codeChallenge
	return pca.executeTokenRequestWithCacheWrite(req, authParams)
}

// executeTokenRequestWithoutCacheWrite stuff
func (pca *PublicClientApplication) executeTokenRequestWithoutCacheWrite(
	req requests.TokenRequester,
	authParams *msalbase.AuthParametersInternal) (IAuthenticationResult, error) {
	tokenResponse, err := req.Execute()
	if err == nil {
		// todo: is account being nil proper here?
		return msalbase.CreateAuthenticationResult(tokenResponse, nil)
	}
	return nil, err
}

// executeTokenRequestWithCacheWrite stuff
func (pca *PublicClientApplication) executeTokenRequestWithCacheWrite(
	req requests.TokenRequester,
	authParams *msalbase.AuthParametersInternal) (IAuthenticationResult, error) {
	tokenResponse, err := req.Execute()
	if err == nil {
		if pca.cacheAccessor != nil {
			pca.cacheAccessor.BeforeCacheAccess(pca.cacheContext)
		}
		account, err := pca.cacheContext.cache.CacheTokenResponse(authParams, tokenResponse)
		if pca.cacheAccessor != nil {
			pca.cacheAccessor.AfterCacheAccess(pca.cacheContext)
		}
		if err != nil {
			return nil, err
		}
		return msalbase.CreateAuthenticationResult(tokenResponse, account)
	}
	return nil, err
}

func (pca *PublicClientApplication) GetAccounts() []IAccount {
	returnedAccounts := []IAccount{}
	if pca.cacheAccessor != nil {
		pca.cacheAccessor.BeforeCacheAccess(pca.cacheContext)
	}
	accounts := pca.cacheContext.cache.GetAllAccounts()
	if pca.cacheAccessor != nil {
		pca.cacheAccessor.AfterCacheAccess(pca.cacheContext)
	}
	for _, acc := range accounts {
		returnedAccounts = append(returnedAccounts, acc)
	}
	return returnedAccounts
}
