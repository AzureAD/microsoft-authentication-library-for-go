// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"encoding/json"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

type cacheSerializationContract struct {
	AccessTokens  map[string]*accessTokenCacheItem  `json:"AccessToken"`
	RefreshTokens map[string]*refreshTokenCacheItem `json:"RefreshToken"`
	IDTokens      map[string]*idTokenCacheItem      `json:"IdToken"`
	Accounts      map[string]*msalbase.Account      `json:"Account"`
	AppMetadata   map[string]*appMetadata           `json:"AppMetadata"`
	snapshot      map[string]interface{}
}

func createCacheSerializationContract() *cacheSerializationContract {
	at := make(map[string]*accessTokenCacheItem)
	rt := make(map[string]*refreshTokenCacheItem)
	id := make(map[string]*idTokenCacheItem)
	ac := make(map[string]*msalbase.Account)
	app := make(map[string]*appMetadata)
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
						appMetadata := &appMetadata{}
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
	accessTokens := make(map[string]interface{})
	for k, v := range s.AccessTokens {
		jsonNode, err := v.convertToJSONMap()
		if err == nil {
			accessTokens[k] = jsonNode
		}
	}
	j["AccessToken"] = accessTokens
	refreshTokens := make(map[string]interface{})
	for k, v := range s.RefreshTokens {
		jsonNode, err := v.convertToJSONMap()
		if err == nil {
			refreshTokens[k] = jsonNode
		}
	}
	j["RefreshToken"] = refreshTokens
	idTokens := make(map[string]interface{})
	for k, v := range s.IDTokens {
		jsonNode, err := v.convertToJSONMap()
		if err == nil {
			idTokens[k] = jsonNode
		}
	}
	j["IdToken"] = idTokens
	accounts := make(map[string]interface{})
	for k, v := range s.Accounts {
		jsonNode, err := v.ConvertToJSONMap()
		if err == nil {
			accounts[k] = jsonNode
		}
	}
	j["Account"] = accounts
	appMetadatas := make(map[string]interface{})
	for k, v := range s.AppMetadata {
		jsonNode, err := v.convertToJSONMap()
		if err == nil {
			appMetadatas[k] = jsonNode
		}
	}
	j["AppMetadata"] = appMetadatas
	return json.Marshal(j)
}
