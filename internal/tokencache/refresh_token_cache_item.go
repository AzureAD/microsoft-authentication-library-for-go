// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"encoding/json"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

type refreshTokenCacheItem struct {
	HomeAccountID    *string `json:"home_account_id,omitempty"`
	Environment      *string `json:"environment,omitempty"`
	CredentialType   *string `json:"credential_type,omitempty"`
	ClientID         *string `json:"client_id,omitempty"`
	FamilyID         *string `json:"family_id,omitempty"`
	Secret           *string `json:"secret,omitempty"`
	Realm            *string `json:"realm,omitempty"`
	Target           *string `json:"target,omitempty"`
	additionalFields map[string]interface{}
}

func createRefreshTokenCacheItem(homeAccountID string,
	environment string,
	clientID string,
	refreshToken string,
	familyID string,
) *refreshTokenCacheItem {
	credentialType := msalbase.CredentialTypeRefreshToken
	rt := &refreshTokenCacheItem{
		HomeAccountID:  &homeAccountID,
		Environment:    &environment,
		CredentialType: &credentialType,
		ClientID:       &clientID,
		FamilyID:       &familyID,
		Secret:         &refreshToken,
	}
	return rt
}

func (rt *refreshTokenCacheItem) CreateKey() string {
	var fourth string
	if msalbase.GetStringFromPointer(rt.FamilyID) == "" {
		fourth = msalbase.GetStringFromPointer(rt.ClientID)
	} else {
		fourth = msalbase.GetStringFromPointer(rt.FamilyID)
	}
	keyParts := []string{
		msalbase.GetStringFromPointer(rt.HomeAccountID),
		msalbase.GetStringFromPointer(rt.Environment),
		msalbase.GetStringFromPointer(rt.CredentialType),
		fourth,
	}
	return strings.Join(keyParts, msalbase.CacheKeySeparator)
}

func (rt *refreshTokenCacheItem) GetSecret() string {
	return msalbase.GetStringFromPointer(rt.Secret)
}

func (rt *refreshTokenCacheItem) populateFromJSONMap(j map[string]interface{}) error {
	rt.HomeAccountID = msalbase.ExtractStringPointerForCache(j, msalbase.JSONHomeAccountID)
	rt.Environment = msalbase.ExtractStringPointerForCache(j, msalbase.JSONEnvironment)
	rt.CredentialType = msalbase.ExtractStringPointerForCache(j, msalbase.JSONCredentialType)
	rt.ClientID = msalbase.ExtractStringPointerForCache(j, msalbase.JSONClientID)
	rt.FamilyID = msalbase.ExtractStringPointerForCache(j, msalbase.JSONFamilyID)
	rt.Secret = msalbase.ExtractStringPointerForCache(j, msalbase.JSONSecret)
	rt.Target = msalbase.ExtractStringPointerForCache(j, msalbase.JSONTarget)
	rt.Realm = msalbase.ExtractStringPointerForCache(j, msalbase.JSONRealm)
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
