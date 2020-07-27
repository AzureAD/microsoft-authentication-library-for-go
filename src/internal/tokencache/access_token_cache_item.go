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
	HomeAccountID                  *string `json:"home_account_id,omitempty"`
	Environment                    *string `json:"environment,omitempty"`
	Realm                          *string `json:"realm,omitempty"`
	CredentialType                 *string `json:"credential_type,omitempty"`
	ClientID                       *string `json:"client_id,omitempty"`
	Secret                         *string `json:"secret,omitempty"`
	Scopes                         *string `json:"target,omitempty"`
	ExpiresOnUnixTimestamp         *string `json:"expires_on,omitempty"`
	ExtendedExpiresOnUnixTimestamp *string `json:"extended_expires_on,omitempty"`
	CachedAt                       *string `json:"cached_at,omitempty"`
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
	credentialType := msalbase.CredentialTypeAccessToken
	cachedAtString := strconv.FormatInt(cachedAt, 10)
	expiresOnString := strconv.FormatInt(expiresOn, 10)
	extExpiresOnString := strconv.FormatInt(extendedExpiresOn, 10)
	at := &accessTokenCacheItem{
		HomeAccountID:                  &homeAccountID,
		Environment:                    &environment,
		Realm:                          &realm,
		CredentialType:                 &credentialType,
		ClientID:                       &clientID,
		Secret:                         &accessToken,
		Scopes:                         &scopes,
		CachedAt:                       &cachedAtString,
		ExpiresOnUnixTimestamp:         &expiresOnString,
		ExtendedExpiresOnUnixTimestamp: &extExpiresOnString,
		additionalFields:               make(map[string]interface{}),
	}
	return at
}

func (s *accessTokenCacheItem) CreateKey() string {
	keyParts := []string{msalbase.GetStringFromPointer(s.HomeAccountID),
		msalbase.GetStringFromPointer(s.Environment),
		msalbase.GetStringFromPointer(s.CredentialType),
		msalbase.GetStringFromPointer(s.ClientID),
		msalbase.GetStringFromPointer(s.Realm),
		msalbase.GetStringFromPointer(s.Scopes)}
	return strings.Join(keyParts, msalbase.CacheKeySeparator)
}

func (s *accessTokenCacheItem) GetSecret() string {
	return msalbase.GetStringFromPointer(s.Secret)
}

func (s *accessTokenCacheItem) GetExpiresOn() string {
	return msalbase.GetStringFromPointer(s.ExpiresOnUnixTimestamp)
}

func (s *accessTokenCacheItem) GetScopes() string {
	return msalbase.GetStringFromPointer(s.Scopes)
}

func (s *accessTokenCacheItem) populateFromJSONMap(j map[string]interface{}) error {

	s.HomeAccountID = msalbase.ExtractStringPointerForCache(j, msalbase.JSONHomeAccountID)
	s.Environment = msalbase.ExtractStringPointerForCache(j, msalbase.JSONEnvironment)
	s.Realm = msalbase.ExtractStringPointerForCache(j, msalbase.JSONRealm)
	s.CredentialType = msalbase.ExtractStringPointerForCache(j, msalbase.JSONCredentialType)
	s.ClientID = msalbase.ExtractStringPointerForCache(j, msalbase.JSONClientID)
	s.Secret = msalbase.ExtractStringPointerForCache(j, msalbase.JSONSecret)
	s.Scopes = msalbase.ExtractStringPointerForCache(j, msalbase.JSONTarget)
	s.CachedAt = msalbase.ExtractStringPointerForCache(j, msalbase.JSONCachedAt)
	s.ExpiresOnUnixTimestamp = msalbase.ExtractStringPointerForCache(j, msalbase.JSONExpiresOn)
	s.ExtendedExpiresOnUnixTimestamp = msalbase.ExtractStringPointerForCache(j, msalbase.JSONExtExpiresOn)
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
