// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"encoding/json"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type cacheSerializationContract struct {
	AccessTokens  map[string]*accessTokenCacheItem  `json:"AccessToken"`
	RefreshTokens map[string]*refreshTokenCacheItem `json:"RefreshToken"`
	IDTokens      map[string]*idTokenCacheItem      `json:"IdToken"`
	Accounts      map[string]*msalbase.Account      `json:"Account"`
	AppMetadata   map[string]*AppMetadata           `json:"AppMetadata"`
	snapshot      map[string]interface{}
}

func createCacheSerializationContract() *cacheSerializationContract {
	at := make(map[string]*accessTokenCacheItem)
	rt := make(map[string]*refreshTokenCacheItem)
	id := make(map[string]*idTokenCacheItem)
	ac := make(map[string]*msalbase.Account)
	app := make(map[string]*AppMetadata)
	c := &cacheSerializationContract{
		AccessTokens:  at,
		RefreshTokens: rt,
		IDTokens:      id,
		Accounts:      ac,
		AppMetadata:   app,
		snapshot:      make(map[string]interface{}),
	}
	return c
}

func (s *cacheSerializationContract) UnmarshalJSON(data []byte) error {
	j := make(map[string]interface{})
	err := json.Unmarshal(data, &j)
	if err != nil {
		return err
	}
	for jsonKey := range j {
		if jsonKey == "AccessToken" {
			if accessTokens, ok := j["AccessToken"].(map[string]interface{}); ok {
				for k, v := range accessTokens {
					if item, ok := v.(map[string]interface{}); ok {
						accessToken := &accessTokenCacheItem{}
						accessToken.populateFromJSONMap(item)
						s.AccessTokens[k] = accessToken
					}
				}
			}
		} else if jsonKey == "RefreshToken" {
			if refreshTokens, ok := j["RefreshToken"].(map[string]interface{}); ok {
				for k, v := range refreshTokens {
					if item, ok := v.(map[string]interface{}); ok {
						refreshToken := &refreshTokenCacheItem{}
						refreshToken.populateFromJSONMap(item)
						s.RefreshTokens[k] = refreshToken
					}
				}
			}
		} else if jsonKey == "IdToken" {
			if idTokens, ok := j["IdToken"].(map[string]interface{}); ok {
				for k, v := range idTokens {
					if item, ok := v.(map[string]interface{}); ok {
						idToken := &idTokenCacheItem{}
						idToken.populateFromJSONMap(item)
						s.IDTokens[k] = idToken
					}
				}
			}
		} else if jsonKey == "Account" {
			if accounts, ok := j["Account"].(map[string]interface{}); ok {
				for k, v := range accounts {
					if item, ok := v.(map[string]interface{}); ok {
						account := &msalbase.Account{}
						account.PopulateFromJSONMap(item)
						s.Accounts[k] = account
					}
				}
			}
		} else if jsonKey == "AppMetadata" {
			if appMetadatas, ok := j["AppMetadata"].(map[string]interface{}); ok {
				for k, v := range appMetadatas {
					if item, ok := v.(map[string]interface{}); ok {
						appMetadata := &AppMetadata{}
						appMetadata.populateFromJSONMap(item)
						s.AppMetadata[k] = appMetadata
					}
				}
			}
		} else {
			s.snapshot[jsonKey] = j[jsonKey]
		}
	}
	return nil
}

func (s *cacheSerializationContract) MarshalJSON() ([]byte, error) {
	j := s.snapshot
	j["AccessToken"] = s.AccessTokens
	j["RefreshToken"] = s.RefreshTokens
	j["IdToken"] = s.IDTokens
	j["Account"] = s.Accounts
	j["AppMetadata"] = s.AppMetadata
	return json.Marshal(j)
}

/*
func (s *cacheSerializationContract) MarshalJSON() ([]byte, error) {
	j := make(map[string]interface{})

	// todo: construct a cachekeygenerator specific to the v3 json serialization format instead of using "k" from k,v below

	accessTokens := make(map[string]interface{})
	for k, v := range s.AccessTokens {
		accessTokens[k] = v.toJSONMap()
	}

	j["AccessToken"] = accessTokens

	return json.Marshal(j)
}
*/
