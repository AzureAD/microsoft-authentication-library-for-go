// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"errors"
	"strconv"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"

	log "github.com/sirupsen/logrus"
)

type defaultCacheManager struct {
	storageManager StorageManager
}

//CreateCacheManager creates a defaultCacheManager instance
func CreateCacheManager(storageManager StorageManager) requests.CacheManager {
	cache := &defaultCacheManager{storageManager: storageManager}
	return cache
}

func isAccessTokenValid(accessToken *accessTokenCacheItem) bool {
	cachedAt, err := strconv.ParseInt(accessToken.CachedAt, 10, 64)
	if err != nil {
		log.Info("This access token isn't valid, it was cached at an invalid time.")
		return false
	}
	now := time.Now().Unix()
	if cachedAt > now {
		log.Info("This access token isn't valid, it was cached at an invalid time.")
		return false
	}
	expiresOn, err := strconv.ParseInt(accessToken.ExpiresOnUnixTimestamp, 10, 64)
	if err != nil {
		log.Info("This access token isn't valid, it expires at an invalid time.")
		return false
	}
	if expiresOn <= now+300 {
		log.Info("This access token is expired")
		return false
	}
	return true
}

func (m *defaultCacheManager) GetAllAccounts() []*msalbase.Account {
	return m.storageManager.ReadAllAccounts()
}

func (m *defaultCacheManager) Serialize() (string, error) {
	return m.storageManager.Serialize()
}

func (m *defaultCacheManager) Deserialize(data []byte) error {
	return m.storageManager.Deserialize(data)
}

func (m *defaultCacheManager) TryReadCache(authParameters *msalbase.AuthParametersInternal, webRequestManager requests.WebRequestManager) (*msalbase.StorageTokenResponse, error) {
	homeAccountID := authParameters.HomeaccountID
	realm := authParameters.AuthorityInfo.Tenant
	clientID := authParameters.ClientID
	scopes := authParameters.Scopes
	aadInstanceDiscovery := requests.CreateAadInstanceDiscovery(webRequestManager)
	metadata, err := aadInstanceDiscovery.GetMetadataEntry(authParameters.AuthorityInfo)
	if err != nil {
		return nil, err
	}
	log.Infof("Querying the cache for homeAccountId '%s' environments '%v' realm '%s' clientId '%s' scopes:'%v'", homeAccountID, metadata.Aliases, realm, clientID, scopes)

	accessToken := m.storageManager.ReadAccessToken(homeAccountID, metadata.Aliases, realm, clientID, scopes)
	if accessToken != nil {
		if !isAccessTokenValid(accessToken) {
			accessToken = nil
		}
	}
	idToken := m.storageManager.ReadIDToken(homeAccountID, metadata.Aliases, realm, clientID)
	appMetadata := m.storageManager.ReadAppMetadata(metadata.Aliases, clientID)
	var familyID string
	if appMetadata != nil {
		familyID = appMetadata.FamilyID
	}
	refreshToken := m.storageManager.ReadRefreshToken(homeAccountID, metadata.Aliases, familyID, clientID)
	account := m.storageManager.ReadAccount(homeAccountID, metadata.Aliases, realm)
	return msalbase.CreateStorageTokenResponse(accessToken, refreshToken, idToken, account), nil
}

func (m *defaultCacheManager) CacheTokenResponse(authParameters *msalbase.AuthParametersInternal, tokenResponse *msalbase.TokenResponse) (*msalbase.Account, error) {
	var err error
	authParameters.HomeaccountID = tokenResponse.GetHomeAccountIDFromClientInfo()
	homeAccountID := authParameters.HomeaccountID
	environment := authParameters.AuthorityInfo.Host
	realm := authParameters.AuthorityInfo.Tenant
	clientID := authParameters.ClientID
	target := msalbase.ConcatenateScopes(tokenResponse.GrantedScopes)

	log.Infof("Writing to the cache for homeAccountId '%s' environment '%s' realm '%s' clientId '%s' target '%s'", homeAccountID, environment, realm, clientID, target)

	cachedAt := time.Now().Unix()

	if tokenResponse.HasRefreshToken() {
		refreshToken := createRefreshTokenCacheItem(homeAccountID, environment, clientID, tokenResponse.RefreshToken, tokenResponse.FamilyID)
		err = m.storageManager.WriteRefreshToken(refreshToken)
		if err != nil {
			return nil, err
		}
	}

	if tokenResponse.HasAccessToken() {
		expiresOn := tokenResponse.ExpiresOn.Unix()
		extendedExpiresOn := tokenResponse.ExtExpiresOn.Unix()
		accessToken := createAccessTokenCacheItem(homeAccountID,
			environment,
			realm,
			clientID,
			cachedAt,
			expiresOn,
			extendedExpiresOn,
			target,
			tokenResponse.AccessToken)
		if isAccessTokenValid(accessToken) {
			err = m.storageManager.WriteAccessToken(accessToken)
			if err != nil {
				return nil, err
			}
		}
	}
	var account *msalbase.Account
	idTokenJwt := tokenResponse.IDToken

	if idTokenJwt != nil {
		idToken := createIDTokenCacheItem(homeAccountID, environment, realm, clientID, idTokenJwt.RawToken)
		err = m.storageManager.WriteIDToken(idToken)

		if err != nil {
			return nil, err
		}

		localAccountID := idTokenJwt.GetLocalAccountID()
		authorityType := authParameters.AuthorityInfo.AuthorityType

		account = msalbase.NewAccount(
			homeAccountID,
			environment,
			realm,
			localAccountID,
			authorityType,
			idTokenJwt.PreferredUsername,
		)
		err = m.storageManager.WriteAccount(account)

		if err != nil {
			return nil, err
		}
	}

	appMetadata := createAppMetadata(tokenResponse.FamilyID, clientID, environment)

	err = m.storageManager.WriteAppMetadata(appMetadata)

	if err != nil {
		return nil, err
	}
	return account, nil
}

func (m *defaultCacheManager) DeleteCachedRefreshToken(authParameters *msalbase.AuthParametersInternal) error {
	return errors.New("Not implemented")
}
