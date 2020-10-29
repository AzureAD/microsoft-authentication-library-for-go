// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"encoding/json"
	"strings"
)

//Account represents a user's account with information from an ID token
type Account struct {
	HomeAccountID     string `json:"home_account_id,omitempty"`
	Environment       string `json:"environment,omitempty"`
	Realm             string `json:"realm,omitempty"`
	LocalAccountID    string `json:"local_account_id,omitempty"`
	AuthorityType     string `json:"authority_type,omitempty"`
	PreferredUsername string `json:"username,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	Name              string `json:"name,omitempty"`
	AlternativeID     string `json:"alternative_account_id,omitempty"`
	RawClientInfo     string `json:"client_info,omitempty"`
	additionalFields  map[string]interface{}
}

// NewAccount creates an account.
func NewAccount(homeAccountID, env, realm, localAccountID, authorityType, username string) *Account {
	return &Account{
		HomeAccountID:     homeAccountID,
		Environment:       env,
		Realm:             realm,
		LocalAccountID:    localAccountID,
		AuthorityType:     authorityType,
		PreferredUsername: username,
	}
}

// CreateKey creates the key for storing accounts in the cache.
func (acc *Account) CreateKey() string {
	return strings.Join([]string{acc.HomeAccountID, acc.Environment, acc.Realm}, CacheKeySeparator)
}

//GetUsername returns the username of an account
func (acc *Account) GetUsername() string {
	return acc.PreferredUsername
}

//GetHomeAccountID returns the home account ID of an account
func (acc *Account) GetHomeAccountID() string {
	return acc.HomeAccountID
}

//GetEnvironment returns the environment of an account
func (acc *Account) GetEnvironment() string {
	return acc.Environment
}

//PopulateFromJSONMap populates an account object from a map (used for cache deserialization)
func (acc *Account) PopulateFromJSONMap(j map[string]interface{}) error {
	acc.HomeAccountID = GetStringKey(j, JSONHomeAccountID)
	acc.Environment = GetStringKey(j, JSONEnvironment)
	acc.Realm = GetStringKey(j, JSONRealm)
	acc.LocalAccountID = GetStringKey(j, JSONLocalAccountID)
	acc.AuthorityType = GetStringKey(j, JSONAuthorityType)
	acc.PreferredUsername = GetStringKey(j, JSONUsername)
	acc.AlternativeID = GetStringKey(j, JSONAlternativeID)
	acc.GivenName = GetStringKey(j, JSONGivenName)
	acc.FamilyName = GetStringKey(j, JSONFamilyName)
	acc.MiddleName = GetStringKey(j, JSONMiddleName)
	acc.Name = GetStringKey(j, JSONName)
	acc.RawClientInfo = GetStringKey(j, JSONClientInfo)
	acc.additionalFields = j
	return nil
}

//ConvertToJSONMap converts an account object to a map (used for cache serialization)
func (acc *Account) ConvertToJSONMap() (map[string]interface{}, error) {
	accountMap, err := json.Marshal(acc)
	if err != nil {
		return nil, err
	}
	newMap := make(map[string]interface{})
	err = json.Unmarshal(accountMap, &newMap)
	if err != nil {
		return nil, err
	}
	for k, v := range acc.additionalFields {
		newMap[k] = v
	}
	return newMap, nil
}
