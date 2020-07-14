// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"encoding/json"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
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

func CreateRefreshTokenCacheItem(homeAccountID string,
	environment string,
	clientID string,
	refreshToken string,
	familyID string,
) *refreshTokenCacheItem {
	rt := &refreshTokenCacheItem{
		HomeAccountID:  homeAccountID,
		Environment:    environment,
		CredentialType: msalbase.CredentialTypeOauth2RefreshToken.ToString(),
		ClientID:       clientID,
		FamilyID:       familyID,
		Secret:         refreshToken,
	}
	return rt
}

func (rt *refreshTokenCacheItem) CreateKey() string {
	var fourth string
	if rt.FamilyID == "" {
		fourth = rt.ClientID
	} else {
		fourth = rt.FamilyID
	}
	keyParts := []string{rt.HomeAccountID, rt.Environment, rt.CredentialType, fourth}
	return strings.Join(keyParts, msalbase.CacheKeySeparator)
}

func (rt *refreshTokenCacheItem) GetSecret() string {
	return rt.Secret
}

func (rt *refreshTokenCacheItem) populateFromJSONMap(j map[string]interface{}) error {
	rt.HomeAccountID = msalbase.ExtractExistingOrEmptyString(j, "home_account_id")
	rt.Environment = msalbase.ExtractExistingOrEmptyString(j, "environment")
	rt.CredentialType = msalbase.ExtractExistingOrEmptyString(j, "credential_type")
	rt.ClientID = msalbase.ExtractExistingOrEmptyString(j, "client_id")
	rt.FamilyID = msalbase.ExtractExistingOrEmptyString(j, "family_id")
	rt.Secret = msalbase.ExtractExistingOrEmptyString(j, "secret")
	rt.Target = msalbase.ExtractExistingOrEmptyString(j, "target")
	rt.Realm = msalbase.ExtractExistingOrEmptyString(j, "realm")
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
