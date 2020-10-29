// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"encoding/json"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

type idTokenCacheItem struct {
	HomeAccountID    string `json:"home_account_id,omitempty"`
	Environment      string `json:"environment,omitempty"`
	Realm            string `json:"realm,omitempty"`
	CredentialType   string `json:"credential_type,omitempty"`
	ClientID         string `json:"client_id,omitempty"`
	Secret           string `json:"secret,omitempty"`
	additionalFields map[string]interface{}
}

func createIDTokenCacheItem(homeID, env, realm, clientID, idToken string) *idTokenCacheItem {
	return &idTokenCacheItem{
		HomeAccountID:  homeID,
		Environment:    env,
		Realm:          realm,
		CredentialType: msalbase.CredentialTypeIDToken,
		ClientID:       clientID,
		Secret:         idToken,
	}
}

func (id *idTokenCacheItem) CreateKey() string {
	return strings.Join(
		[]string{id.HomeAccountID, id.Environment, id.CredentialType, id.ClientID, id.Realm},
		msalbase.CacheKeySeparator,
	)
}

func (id *idTokenCacheItem) GetSecret() string {
	return id.Secret
}

func (id *idTokenCacheItem) populateFromJSONMap(j map[string]interface{}) error {
	id.HomeAccountID = msalbase.GetStringKey(j, msalbase.JSONHomeAccountID)
	id.Environment = msalbase.GetStringKey(j, msalbase.JSONEnvironment)
	id.Realm = msalbase.GetStringKey(j, msalbase.JSONRealm)
	id.CredentialType = msalbase.GetStringKey(j, msalbase.JSONCredentialType)
	id.ClientID = msalbase.GetStringKey(j, msalbase.JSONClientID)
	id.Secret = msalbase.GetStringKey(j, msalbase.JSONSecret)
	id.additionalFields = j
	return nil
}

func (id *idTokenCacheItem) convertToJSONMap() (map[string]interface{}, error) {
	idMap, err := json.Marshal(id)
	if err != nil {
		return nil, err
	}
	newMap := make(map[string]interface{})
	err = json.Unmarshal(idMap, &newMap)
	if err != nil {
		return nil, err
	}
	for k, v := range id.additionalFields {
		newMap[k] = v
	}
	return newMap, nil
}
