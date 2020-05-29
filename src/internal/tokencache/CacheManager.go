// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"errors"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

	log "github.com/sirupsen/logrus"
)

type cacheManager struct {
	storageManager IStorageManager
}

func CreateCacheManager(storageManager IStorageManager) msalbase.ICacheManager {
	cache := &cacheManager{storageManager}
	return cache
}

func isAccessTokenValid(accessToken *msalbase.Credential) bool {
	// const int64_t now = TimeUtils::GetSecondsFromEpochNow();
	// // If the token expires in less than 5 minutes (300 seconds), consider it invalid to guarantee that valid access
	// // tokens have a time windows to use them.
	// if (accessToken.GetExpiresOn() <= now + 300)
	// {
	//     log.Info("The access token is expired");
	//     return false;
	// }
	// // Also check that the token isn't cached in the "future" which can happen if the user changed the clock, in which
	// // case the token should be conidered invalid, since it can't really be validated.
	// if (accessToken.GetCachedAt() > now)
	// {
	//     log.Info("The access token is marked with a 'future' timestamp, it's considered invalid");
	//     return false;
	// }

	return true
}

func (m *cacheManager) TryReadCache(authParameters *msalbase.AuthParametersInternal) (*msalbase.StorageTokenResponse, error) {

	emptyCorrelationID := ""
	emptyFamilyID := ""
	homeAccountID := authParameters.GetHomeAccountID()
	// authorityURI := authParameters.GetAuthorityInfo().GetCanonicalAuthorityURI()
	// shared_ptr<Uri> authority = authParameters.GetAuthority();
	environment := "" // todo:  authority.GetEnvironment();
	realm := ""       // authParameters.GetAuthorityInfo().GetRealm() // todo: authority->GetRealm();
	clientID := authParameters.GetClientID()
	target := strings.Join(authParameters.GetScopes(), " ")

	log.Tracef("Querying the cache for homeAccountId '%s' environment '%s' realm '%s' clientId '%s' target:'%s'", homeAccountID, environment, realm, clientID, target)

	if homeAccountID == "" || environment == "" || realm == "" || clientID == "" || target == "" {
		log.Warn("Skipping the tokens cache lookup, one of the primary keys is empty")
		return nil, errors.New("Skipping the tokens cache lookup, one of the primary keys is empty")
	}

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

	var accessToken *msalbase.Credential
	var refreshToken *msalbase.Credential
	var idToken *msalbase.Credential

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
}

func (m *cacheManager) CacheTokenResponse(authParameters *msalbase.AuthParametersInternal, tokenResponse *msalbase.TokenResponse) (*msalbase.Account, error) {
	homeAccountID := "" // GetHomeAccountId(response)
	// shared_ptr<Uri> authority = authParameters->GetAuthority();
	environment := "" // authority.GetEnvironment()
	realm := ""       // authority->GetRealm();
	clientID := authParameters.GetClientID()
	target := strings.Join(tokenResponse.GetGrantedScopes(), " ")

	log.Tracef("Writing to the cache for homeAccountId '%s' environment '%s' realm '%s' clientId '%s' target '%s'", homeAccountID, environment, realm, clientID, target)

	if homeAccountID == "" || environment == "" || realm == "" || clientID == "" || target == "" {
		log.Warn("Skipping writing data to the tokens cache, one of the primary keys is empty")
		return nil, errors.New("Skipping writing data to the tokens cache, one of the primary keys is empty")
	}

	credentialsToWrite := []*msalbase.Credential{}

	cachedAt := time.Now().Unix()

	if tokenResponse.HasRefreshToken() {
		credentialsToWrite = append(credentialsToWrite, msalbase.CreateCredentialRefreshToken(homeAccountID, environment, clientID, cachedAt, tokenResponse.GetRefreshToken(), ""))
	}

	if tokenResponse.HasAccessToken() {
		expiresOn := tokenResponse.GetExpiresOn().Unix()
		extendedExpiresOn := tokenResponse.GetExtendedExpiresOn().Unix()

		accessToken := msalbase.CreateCredentialAccessToken(
			homeAccountID,
			environment,
			realm,
			clientID,
			target,
			cachedAt,
			expiresOn,
			extendedExpiresOn,
			tokenResponse.GetAccessToken(),
			"") // _emptyAdditionalFieldsJson

		if isAccessTokenValid(accessToken) {
			credentialsToWrite = append(credentialsToWrite, accessToken)
		}
	}

	idTokenJwt := tokenResponse.GetIDToken()

	if !idTokenJwt.IsEmpty() {
		credentialsToWrite = append(credentialsToWrite, msalbase.CreateCredentialIdToken(homeAccountID, environment, realm, clientID, cachedAt, idTokenJwt.GetRaw(), ""))
	}

	emptyCorrelationID := ""

	operationStatus, err := m.storageManager.WriteCredentials(emptyCorrelationID, credentialsToWrite)
	if err != nil {
		return nil, err
	}

	if operationStatus.StatusType != OperationStatusTypeSuccess {
		log.Warn("Error writing credentials to the cache")
	}

	if idTokenJwt.IsEmpty() {
		return nil, nil
	}

	localAccountID := "" // GetLocalAccountId(idTokenJwt)
	authorityType := authParameters.GetAuthorityInfo().GetAuthorityType()

	account := msalbase.CreateAccount(
		homeAccountID,
		environment,
		realm,
		localAccountID,
		authorityType,
		idTokenJwt.GetPreferredUsername(),
		idTokenJwt.GetGivenName(),
		idTokenJwt.GetFamilyName(),
		idTokenJwt.GetMiddleName(),
		idTokenJwt.GetName(),
		idTokenJwt.GetAlternativeId(),
		tokenResponse.GetRawClientInfo(),
		"")

	operationStatus, err = m.storageManager.WriteAccount(emptyCorrelationID, account)

	if operationStatus.StatusType != OperationStatusTypeSuccess {
		log.Warn("Error writing an account to the cache")
	}

	return account, nil
}

func (m *cacheManager) DeleteCachedRefreshToken(authParameters *msalbase.AuthParametersInternal) error {
	homeAccountID := "" // todo: authParameters.GetAccountId()
	environment := ""   // authParameters.GetAuthorityInfo().GetEnvironment()
	clientID := authParameters.GetClientID()

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
