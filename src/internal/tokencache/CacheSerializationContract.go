// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import "encoding/json"

type cacheSerializationContract struct {
	AccessTokens  map[string]*accessTokenCacheItem
	RefreshTokens map[string]*refreshTokenCacheItem
	IDTokens      map[string]*idTokenCacheItem
	Accounts      map[string]*accountCacheItem
}

func createCacheSerializationContract() *cacheSerializationContract {
	at := make(map[string]*accessTokenCacheItem)
	rt := make(map[string]*refreshTokenCacheItem)
	id := make(map[string]*idTokenCacheItem)
	ac := make(map[string]*accountCacheItem)
	c := &cacheSerializationContract{at, rt, id, ac}
	return c
}

func (s *cacheSerializationContract) UnmarshalJSON(b []byte) error {
	j := make(map[string]interface{})
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}

	if accessTokens, ok := j["AccessToken"].(map[string]interface{}); ok {
		for k, v := range accessTokens {
			if item, ok := v.(map[string]interface{}); ok {
				accessToken := &accessTokenCacheItem{}
				accessToken.populateFromJSONMap(item)
				s.AccessTokens[k] = accessToken
			}
		}
	}

	return nil
}

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
