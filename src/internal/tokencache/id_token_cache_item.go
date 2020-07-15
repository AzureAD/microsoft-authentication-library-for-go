// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"encoding/json"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type idTokenCacheItem struct {
	HomeAccountID    *string `json:"home_account_id,omitempty"`
	Environment      *string `json:"environment,omitempty"`
	Realm            *string `json:"realm,omitempty"`
	CredentialType   *string `json:"credential_type,omitempty"`
	ClientID         *string `json:"client_id,omitempty"`
	Secret           *string `json:"secret,omitempty"`
	additionalFields map[string]interface{}
}

func CreateIDTokenCacheItem(homeAccountID string,
	environment string,
	realm string,
	clientID string,
	idToken string) *idTokenCacheItem {
	credentialType := msalbase.CredentialTypeOidcIDToken.ToString()
	id := &idTokenCacheItem{
		HomeAccountID:  &homeAccountID,
		Environment:    &environment,
		Realm:          &realm,
		CredentialType: &credentialType,
		ClientID:       &clientID,
		Secret:         &idToken,
	}
	return id
}

func (id *idTokenCacheItem) CreateKey() string {
	keyParts := []string{*id.HomeAccountID, *id.Environment, *id.CredentialType, *id.ClientID, *id.Realm}
	return strings.Join(keyParts, msalbase.CacheKeySeparator)
}

func (id *idTokenCacheItem) GetSecret() string {
	return *id.Secret
}

func (id *idTokenCacheItem) populateFromJSONMap(j map[string]interface{}) error {
	id.HomeAccountID = msalbase.ExtractStringPointerForCache(j, "home_account_id")
	id.Environment = msalbase.ExtractStringPointerForCache(j, "environment")
	id.Realm = msalbase.ExtractStringPointerForCache(j, "realm")
	id.CredentialType = msalbase.ExtractStringPointerForCache(j, "credential_type")
	id.ClientID = msalbase.ExtractStringPointerForCache(j, "client_id")
	id.Secret = msalbase.ExtractStringPointerForCache(j, "secret")
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
