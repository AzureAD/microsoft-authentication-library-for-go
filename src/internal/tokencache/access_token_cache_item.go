// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"strconv"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type accessTokenCacheItem struct {
	HomeAccountID                  string
	Environment                    string
	Realm                          string
	CredentialType                 string
	ClientID                       string
	Secret                         string
	Scopes                         string
	ExpiresOnUnixTimestamp         string
	ExtendedExpiresOnUnixTimestamp string
	CachedAt                       string
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

func (s *accessTokenCacheItem) convertToJSONMap() map[string]interface{} {
	jsonMap := s.additionalFields
	jsonMap["home_account_id"] = s.HomeAccountID
	jsonMap["environment"] = s.Environment
	jsonMap["realm"] = s.Realm
	jsonMap["credential_type"] = s.CredentialType
	jsonMap["client_id"] = s.ClientID
	jsonMap["secret"] = s.Secret
	jsonMap["target"] = s.Scopes
	jsonMap["cached_at"] = s.CachedAt
	jsonMap["expires_on"] = s.ExpiresOnUnixTimestamp
	if s.ExtendedExpiresOnUnixTimestamp != "" {
		jsonMap["extended_expires_on"] = s.ExtendedExpiresOnUnixTimestamp
	}
	return jsonMap
}

/*
func (s *accessTokenCacheItem) UnmarshalJSON(b []byte) error {
	j := make(map[string]interface{})
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}

	return s.populateFromJSONMap(j)
}

func (s *accessTokenCacheItem) toJSONMap() map[string]interface{} {
	j := make(map[string]interface{})
	for k, v := range s.AdditionalFields {
		j[k] = v
	}

	j["home_account_id"] = s.HomeAccountID

	return j
}

func (s *accessTokenCacheItem) MarshalJSON() ([]byte, error) {
	j := s.toJSONMap()
	return json.Marshal(j)
}
*/
