// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"encoding/json"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

type refreshTokenCacheItem struct {
	HomeAccountID    string `json:"home_account_id,omitempty"`
	Environment      string `json:"environment,omitempty"`
	CredentialType   string `json:"credential_type,omitempty"`
	ClientID         string `json:"client_id,omitempty"`
	FamilyID         string `json:"family_id,omitempty"`
	Secret           string `json:"secret,omitempty"`
	Realm            string `json:"realm,omitempty"`
	Target           string `json:"target,omitempty"`
	additionalFields map[string]interface{}
}

func createRefreshTokenCacheItem(homeID, env, clientID, refreshToken, familyID string) *refreshTokenCacheItem {
	return &refreshTokenCacheItem{
		HomeAccountID:  homeID,
		Environment:    env,
		CredentialType: msalbase.CredentialTypeRefreshToken,
		ClientID:       clientID,
		FamilyID:       familyID,
		Secret:         refreshToken,
	}
}

func (rt *refreshTokenCacheItem) CreateKey() string {
	var fourth = rt.FamilyID
	if fourth == "" {
		fourth = rt.ClientID
	}

	return strings.Join(
		[]string{rt.HomeAccountID, rt.Environment, rt.CredentialType, fourth},
		msalbase.CacheKeySeparator,
	)
}

func (rt *refreshTokenCacheItem) GetSecret() string {
	return rt.Secret
}

func (rt *refreshTokenCacheItem) populateFromJSONMap(j map[string]interface{}) error {
	rt.HomeAccountID = msalbase.GetStringKey(j, msalbase.JSONHomeAccountID)
	rt.Environment = msalbase.GetStringKey(j, msalbase.JSONEnvironment)
	rt.CredentialType = msalbase.GetStringKey(j, msalbase.JSONCredentialType)
	rt.ClientID = msalbase.GetStringKey(j, msalbase.JSONClientID)
	rt.FamilyID = msalbase.GetStringKey(j, msalbase.JSONFamilyID)
	rt.Secret = msalbase.GetStringKey(j, msalbase.JSONSecret)
	rt.Target = msalbase.GetStringKey(j, msalbase.JSONTarget)
	rt.Realm = msalbase.GetStringKey(j, msalbase.JSONRealm)
	rt.additionalFields = j
	return nil
}

func (rt *refreshTokenCacheItem) convertToJSONMap() (map[string]interface{}, error) {
	refreshMap, err := json.Marshal(rt)
	if err != nil {
		return nil, err
	}
	newMap := make(map[string]interface{})
	err = json.Unmarshal(refreshMap, &newMap)
	if err != nil {
		return nil, err
	}
	for k, v := range rt.additionalFields {
		newMap[k] = v
	}
	return newMap, nil
}
