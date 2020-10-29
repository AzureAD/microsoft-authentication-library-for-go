// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
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

func createAccessTokenCacheItem(homeID, env, realm, clientID string, cachedAt, expiresOn, extendedExpiresOn int64, scopes, token string) *accessTokenCacheItem {
	return &accessTokenCacheItem{
		HomeAccountID:                  homeID,
		Environment:                    env,
		Realm:                          realm,
		CredentialType:                 msalbase.CredentialTypeAccessToken,
		ClientID:                       clientID,
		Secret:                         token,
		Scopes:                         scopes,
		CachedAt:                       strconv.FormatInt(cachedAt, 10),
		ExpiresOnUnixTimestamp:         strconv.FormatInt(expiresOn, 10),
		ExtendedExpiresOnUnixTimestamp: strconv.FormatInt(extendedExpiresOn, 10),
		additionalFields:               make(map[string]interface{}),
	}
}

func (s *accessTokenCacheItem) CreateKey() string {
	return strings.Join(
		[]string{s.HomeAccountID, s.Environment, s.CredentialType, s.ClientID, s.Realm, s.Scopes},
		msalbase.CacheKeySeparator,
	)
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
	s.HomeAccountID = msalbase.GetStringKey(j, msalbase.JSONHomeAccountID)
	s.Environment = msalbase.GetStringKey(j, msalbase.JSONEnvironment)
	s.Realm = msalbase.GetStringKey(j, msalbase.JSONRealm)
	s.CredentialType = msalbase.GetStringKey(j, msalbase.JSONCredentialType)
	s.ClientID = msalbase.GetStringKey(j, msalbase.JSONClientID)
	s.Secret = msalbase.GetStringKey(j, msalbase.JSONSecret)
	s.Scopes = msalbase.GetStringKey(j, msalbase.JSONTarget)
	s.CachedAt = msalbase.GetStringKey(j, msalbase.JSONCachedAt)
	s.ExpiresOnUnixTimestamp = msalbase.GetStringKey(j, msalbase.JSONExpiresOn)
	s.ExtendedExpiresOnUnixTimestamp = msalbase.GetStringKey(j, msalbase.JSONExtExpiresOn)
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
