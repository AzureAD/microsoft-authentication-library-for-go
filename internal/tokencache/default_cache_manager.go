// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"context"
	"errors"
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
	return defaultCacheManager{storageManager: storageManager}
}

func (m defaultCacheManager) GetAllAccounts() ([]msalbase.Account, error) {
	return m.storageManager.ReadAllAccounts()
}

func (m defaultCacheManager) Serialize() (string, error) {
	return m.storageManager.Serialize()
}

func (m defaultCacheManager) Deserialize(data []byte) error {
	return m.storageManager.Deserialize(data)
}

func (m defaultCacheManager) TryReadCache(ctx context.Context, authParameters msalbase.AuthParametersInternal, webRequestManager requests.WebRequestManager) (msalbase.StorageTokenResponse, error) {
	homeAccountID := authParameters.HomeaccountID
	realm := authParameters.AuthorityInfo.Tenant
	clientID := authParameters.ClientID
	scopes := authParameters.Scopes
	aadInstanceDiscovery := requests.CreateAadInstanceDiscovery(webRequestManager)
	metadata, err := aadInstanceDiscovery.GetMetadataEntry(ctx, authParameters.AuthorityInfo)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}
	log.Infof("Querying the cache for homeAccountId '%s' environments '%v' realm '%s' clientId '%s' scopes:'%v'", homeAccountID, metadata.Aliases, realm, clientID, scopes)

	// TODO(reviewer who knows MSAL): The old code here looked bad to me. Basically, if
	// we couldn't read various fields, we just passed along nil values. This seemed
	// broken, so on non-reads I have this returning an error.
	// But I wasn't 100% sure that this was valid behavior. If its not at
	// any level, please elaborate and I will change the code to make this work
	// without nil in a similar way.
	accessToken, err := m.storageManager.ReadAccessToken(homeAccountID, metadata.Aliases, realm, clientID, scopes)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}
	if err := accessToken.Validate(); err != nil {
		return msalbase.StorageTokenResponse{}, err
	}

	idToken, err := m.storageManager.ReadIDToken(homeAccountID, metadata.Aliases, realm, clientID)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}

	appMetadata, err := m.storageManager.ReadAppMetadata(metadata.Aliases, clientID)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}
	familyID := appMetadata.FamilyID

	refreshToken, err := m.storageManager.ReadRefreshToken(homeAccountID, metadata.Aliases, familyID, clientID)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}
	account, err := m.storageManager.ReadAccount(homeAccountID, metadata.Aliases, realm)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}
	return msalbase.CreateStorageTokenResponse(accessToken, refreshToken, idToken, account), nil
}

func (m defaultCacheManager) CacheTokenResponse(authParameters msalbase.AuthParametersInternal, tokenResponse msalbase.TokenResponse) (msalbase.Account, error) {
	authParameters.HomeaccountID = tokenResponse.GetHomeAccountIDFromClientInfo()
	homeAccountID := authParameters.HomeaccountID
	environment := authParameters.AuthorityInfo.Host
	realm := authParameters.AuthorityInfo.Tenant
	clientID := authParameters.ClientID
	target := msalbase.ConcatenateScopes(tokenResponse.GrantedScopes)

	cachedAt := time.Now().Unix()

	var account msalbase.Account

	if tokenResponse.HasRefreshToken() {
		refreshToken := createRefreshTokenCacheItem(homeAccountID, environment, clientID, tokenResponse.RefreshToken, tokenResponse.FamilyID)
		if err := m.storageManager.WriteRefreshToken(refreshToken); err != nil {
			return account, err
		}
	}

	if tokenResponse.HasAccessToken() {
		expiresOn := tokenResponse.ExpiresOn.Unix()
		extendedExpiresOn := tokenResponse.ExtExpiresOn.Unix()
		accessToken := createAccessTokenCacheItem(
			homeAccountID,
			environment,
			realm,
			clientID,
			cachedAt,
			expiresOn,
			extendedExpiresOn,
			target,
			tokenResponse.AccessToken,
		)

		// Since we have a valid access token, cache it before moving on.
		if err := accessToken.Validate(); err == nil {
			if err := m.storageManager.WriteAccessToken(accessToken); err != nil {
				return account, err
			}
		}
	}

	idTokenJwt := tokenResponse.IDToken
	if !idTokenJwt.IsZero() {
		idToken := createIDTokenCacheItem(homeAccountID, environment, realm, clientID, idTokenJwt.RawToken)
		if err := m.storageManager.WriteIDToken(idToken); err != nil {
			return msalbase.Account{}, err
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
		if err := m.storageManager.WriteAccount(account); err != nil {
			return msalbase.Account{}, err
		}
	}

	appMetadata := createAppMetadata(tokenResponse.FamilyID, clientID, environment)

	if err := m.storageManager.WriteAppMetadata(appMetadata); err != nil {
		return msalbase.Account{}, err
	}
	return account, nil
}

func (m defaultCacheManager) DeleteCachedRefreshToken(authParameters msalbase.AuthParametersInternal) error {
	return errors.New("Not implemented")
}
