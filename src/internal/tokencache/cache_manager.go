// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"errors"
	"strconv"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"

	log "github.com/sirupsen/logrus"
)

type cacheManager struct {
	storageManager    IStorageManager
	cacheAccessAspect ICacheAccessAspect
}

func CreateCacheManager(storageManager IStorageManager) *cacheManager {
	cache := &cacheManager{storageManager: storageManager}
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

func (m *cacheManager) GetAllAccounts() []*msalbase.Account {
	return m.storageManager.ReadAllAccounts()
}

func (m *cacheManager) TryReadCache(authParameters *msalbase.AuthParametersInternal) (*msalbase.StorageTokenResponse, error) {
	homeAccountID := authParameters.HomeaccountID
	//environment := authParameters.AuthorityInfo.Host
	realm := authParameters.AuthorityInfo.UserRealmURIPrefix
	clientID := authParameters.ClientID
	scopes := authParameters.Scopes
	/*
		log.Tracef("Querying the cache for homeAccountId '%s' environment '%s' realm '%s' clientId '%s' target:'%s'", homeAccountID, environment, realm, clientID, target)

		if homeAccountID == "" || environment == "" || realm == "" || clientID == "" || target == "" {
			log.Warn("Skipping the tokens cache lookup, one of the primary keys is empty")
			return nil, errors.New("Skipping the tokens cache lookup, one of the primary keys is empty")
		}*/
	aadInstanceDiscovery := requests.CreateAadInstanceDiscovery()
	metadata, err := aadInstanceDiscovery.GetMetadataEntry(authParameters.AuthorityInfo)
	if err != nil {
		return nil, err
	}
	accessToken := m.storageManager.ReadAccessToken(homeAccountID, metadata.Aliases, realm, clientID, scopes)
	if accessToken != nil {
		if !isAccessTokenValid(accessToken) {

			accessToken = nil
		}
	}
	idToken := m.storageManager.ReadIDToken(homeAccountID, metadata.Aliases, realm, clientID)
	appMetadata := m.storageManager.ReadAppMetadata(metadata.Aliases, clientID)
	refreshToken := m.storageManager.ReadRefreshToken(homeAccountID, metadata.Aliases, appMetadata.FamilyID, clientID)
	/*
		readCredentialsResponse, err := m.storageManager.ReadCredentials(
			emptyCorrelationID,
			homeAccountID,
			environment,
			realm,
			clientID,
			emptyFamilyID,
			target,
			map[msalbase.CredentialType]bool{msalbase.CredentialTypeOauth2AccessToken: true, msalbase.CredentialTypeOauth2RefreshToken: true, msalbase.CredentialTypeOidcIDToken: true})

		// todo: better error propagation
		if err != nil {
			return nil, err
		}

		opStatus := readCredentialsResponse.OperationStatus

		if opStatus.StatusType != OperationStatusTypeSuccess {
			log.Warn("Error reading credentials from the cache")
			return nil, nil
		}

		credentials := readCredentialsResponse.Credentials

		if len(credentials) == 0 {
			log.Warn("No credentials found in the cache")
			return nil, nil
		}

		if len(credentials) > 3 {
			// log.Warnf("Expected to read up to 3 credentials from the cache (access token, refresh token, id token), read %s", FormatTokenTypesForLogging(credentials))
		}

		var accessToken msalbase.Credential
		var refreshToken msalbase.Credential
		var idToken msalbase.Credential

		for _, cred := range credentials {

			switch cred.GetCredentialType() {
			case msalbase.CredentialTypeOauth2AccessToken:
				if accessToken != nil {
					log.Warn("More than one access token read from the cache")
				}
				accessToken = cred
				break

			case msalbase.CredentialTypeOauth2RefreshToken:
				if refreshToken != nil {
					log.Warn("More than one refresh token read from the cache")
				}
				refreshToken = cred
				break

			case msalbase.CredentialTypeOidcIDToken:
				if idToken != nil {
					log.Warn("More than one id token read from the cache")
				}
				idToken = cred
				break

			default:
				log.Warn("Read an unknown credential type from the disk cache - ignoring")
				break
			}
		}

		if idToken == nil {
			log.Warn("No id token found in the cache")
		}

		if accessToken == nil {
			log.Warn("No access token found in the cache")
		} else if !isAccessTokenValid(accessToken) {
			m.deleteCachedAccessToken(homeAccountID, environment, realm, clientID, target)
			accessToken = nil
		}

		if accessToken == nil && refreshToken == nil {
			// There's no access token and no refresh token
			log.Warn("No valid access token and no refresh token found in the cache")
			return msalbase.CreateStorageTokenResponse(nil, nil, idToken, nil), nil
		}

		var account *msalbase.Account

		// Search for an account if there's a valid access token. If there's no valid access token, we're going to make a
		// server call anyway and to make a new account.
		if accessToken != nil {
			readAccountResponse, err := m.storageManager.ReadAccount(
				emptyCorrelationID,
				homeAccountID,
				environment,
				realm)

			if err != nil {
				return nil, err
			}

			if readAccountResponse.OperationStatus.StatusType != OperationStatusTypeSuccess {
				log.Warn("Error reading an account from the cache")
			} else {
				account = readAccountResponse.Account
			}

			if account == nil {
				log.Warn("No account found in cache, will still return a token if found")
			}
		}

		return msalbase.CreateStorageTokenResponse(accessToken, refreshToken, idToken, account), nil
	*/
	return nil, nil
}

func (m *cacheManager) CacheTokenResponse(authParameters *msalbase.AuthParametersInternal, tokenResponse *msalbase.TokenResponse) (*msalbase.Account, error) {
	var err error

	authParameters.HomeaccountID = tokenResponse.GetHomeAccountIDFromClientInfo()
	homeAccountID := authParameters.HomeaccountID
	environment := authParameters.AuthorityInfo.Host
	realm := authParameters.AuthorityInfo.UserRealmURIPrefix
	clientID := authParameters.ClientID
	target := msalbase.ConcatenateScopes(tokenResponse.GrantedScopes)

	log.Infof("Writing to the cache for homeAccountId '%s' environment '%s' realm '%s' clientId '%s' target '%s'", homeAccountID, environment, realm, clientID, target)

	if homeAccountID == "" || environment == "" || realm == "" || clientID == "" || target == "" {
		return nil, errors.New("Skipping writing data to the tokens cache, one of the primary keys is empty")
	}

	cachedAt := time.Now().Unix()

	if tokenResponse.HasRefreshToken() {
		refreshToken := CreateRefreshTokenCacheItem(homeAccountID, environment, clientID, tokenResponse.RefreshToken, tokenResponse.FamilyID)
		err = m.storageManager.WriteRefreshToken(refreshToken)
		if err != nil {
			return nil, err
		}
	}

	if tokenResponse.HasAccessToken() {
		expiresOn := tokenResponse.ExpiresOn.Unix()
		extendedExpiresOn := tokenResponse.ExtExpiresOn.Unix()
		accessToken := CreateAccessTokenCacheItem(homeAccountID,
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

	idTokenJwt := tokenResponse.IDToken

	idToken := CreateIDTokenCacheItem(homeAccountID, environment, realm, clientID, idTokenJwt.RawToken)
	m.storageManager.WriteIDToken(idToken)

	if err != nil {
		return nil, err
	}

	localAccountID := idTokenJwt.GetLocalAccountID()
	authorityType := authParameters.AuthorityInfo.AuthorityType

	account := msalbase.CreateAccount(
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

	appMetadata := CreateAppMetadata(tokenResponse.FamilyID, clientID, environment)

	err = m.storageManager.WriteAppMetadata(appMetadata)

	if err != nil {
		return nil, err
	}

	//m.storageManager.ReadAllAccounts(emptyCorrelationID)

	return account, nil
}

func (m *cacheManager) DeleteCachedRefreshToken(authParameters *msalbase.AuthParametersInternal) error {
	homeAccountID := "" // todo: authParameters.GetAccountId()
	environment := ""   // authParameters.GetAuthorityInfo().GetEnvironment()
	clientID := authParameters.ClientID

	emptyCorrelationID := ""
	emptyRealm := ""
	emptyFamilyID := ""
	emptyTarget := ""

	log.Infof("Deleting refresh token from the cache for homeAccountId '%s' environment '%s' clientID '%s'", homeAccountID, environment, clientID)

	if homeAccountID == "" || environment == "" || clientID == "" {
		log.Warn("Failed to delete refresh token from the cache, one of the primary keys is empty")
		return errors.New("Failed to delete refresh token from the cache, one of the primary keys is empty")
	}

	operationStatus, err := m.storageManager.DeleteCredentials(emptyCorrelationID, homeAccountID, environment, emptyRealm, clientID, emptyFamilyID, emptyTarget, map[msalbase.CredentialType]bool{msalbase.CredentialTypeOauth2RefreshToken: true})
	if err != nil {
		return nil
	}

	if operationStatus.StatusType != OperationStatusTypeSuccess {
		log.Warn("Error deleting an invalid refresh token from the cache")
	}

	return nil
}

func (m *cacheManager) deleteCachedAccessToken(homeAccountID string, environment string, realm string, clientID string, target string) error {
	log.Infof("Deleting an access token from the cache for homeAccountId '%s' environment '%s' realm '%s' clientId '%s' target '%s'", homeAccountID, environment, realm, clientID, target)

	emptyCorrelationID := ""
	emptyFamilyID := ""

	operationStatus, err := m.storageManager.DeleteCredentials(emptyCorrelationID, homeAccountID, environment, realm, clientID, emptyFamilyID, target, map[msalbase.CredentialType]bool{msalbase.CredentialTypeOauth2AccessToken: true})

	if err != nil {
		return err
	}

	if operationStatus.StatusType != OperationStatusTypeSuccess {
		log.Warn("Failure deleting an access token from the cache")
	}
	return nil
}
