// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type accessTokenCacheItem struct {
	HomeAccountID                  string `json:"home_account_id,omitempty"`
	Environment                    string `json:"environment,omitempty"`
	Realm                          string `json:"realm,omitempty"`
	CredentialType                 string `json:"credential_type,omitempty"`
	ClientID                       string `json:"client_id,omitempty"`
	Secret                         string `json:"secret,omitempty"`
	Scopes                         string `json:"target,omitempty"`
	ExpiresOnUnixTimestamp         string `json:"expires_on,omitempty"`
	ExtendedExpiresOnUnixTimestamp string `json:"extended_expires_on,omitempty"`
	CachedAt                       string `json:"cached_at,omitempty"`
	additionalFields               map[string]interface{}
}

func CreateAccessTokenCacheItem(homeAccountID string,
	environment string,
	realm string,
	clientID string,
	cachedAt int64,
	expiresOn int64,
	extendedExpiresOn int64,
	scopes string,
	accessToken string) *accessTokenCacheItem {
	at := &accessTokenCacheItem{
		HomeAccountID:                  homeAccountID,
		Environment:                    environment,
		Realm:                          realm,
		CredentialType:                 msalbase.CredentialTypeOauth2AccessToken.ToString(),
		ClientID:                       clientID,
		Secret:                         accessToken,
		Scopes:                         scopes,
		CachedAt:                       strconv.FormatInt(cachedAt, 10),
		ExpiresOnUnixTimestamp:         strconv.FormatInt(expiresOn, 10),
		ExtendedExpiresOnUnixTimestamp: strconv.FormatInt(extendedExpiresOn, 10),
	}
	return at
}

func (s *accessTokenCacheItem) CreateKey() string {
	keyParts := []string{s.HomeAccountID, s.Environment, s.CredentialType, s.ClientID, s.Realm, s.Scopes}
	return strings.Join(keyParts, msalbase.CacheKeySeparator)
}

func (s *accessTokenCacheItem) GetSecret() string {
	return s.Secret
}

func (s *accessTokenCacheItem) GetExpiresOn() string {
	return s.ExpiresOnUnixTimestamp
}

func (s *accessTokenCacheItem) GetScopes() string {
	return s.Scopes
}

func (s *accessTokenCacheItem) populateFromJSONMap(j map[string]interface{}) error {
	s.HomeAccountID = msalbase.ExtractExistingOrEmptyString(j, "home_account_id")
	s.Environment = msalbase.ExtractExistingOrEmptyString(j, "environment")
	s.Realm = msalbase.ExtractExistingOrEmptyString(j, "realm")
	s.CredentialType = msalbase.ExtractExistingOrEmptyString(j, "credential_type")
	s.ClientID = msalbase.ExtractExistingOrEmptyString(j, "client_id")
	s.Secret = msalbase.ExtractExistingOrEmptyString(j, "secret")
	s.Scopes = msalbase.ExtractExistingOrEmptyString(j, "target")
	s.CachedAt = msalbase.ExtractExistingOrEmptyString(j, "cached_at")
	s.ExpiresOnUnixTimestamp = msalbase.ExtractExistingOrEmptyString(j, "expires_on")
	s.ExtendedExpiresOnUnixTimestamp = msalbase.ExtractExistingOrEmptyString(j, "extended_expires_on")
	s.additionalFields = j
	return nil
}

func (s *accessTokenCacheItem) convertToJSONMap() (map[string]interface{}, error) {
	accessMap, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	newMap := make(map[string]interface{})
	err = json.Unmarshal(accessMap, &newMap)
	if err != nil {
		return nil, err
	}
	for k, v := range s.additionalFields {
		newMap[k] = v
	}
	return newMap, nil
}
