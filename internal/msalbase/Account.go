// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"encoding/json"
	"strings"
)

//Account represents a user's account with information from an ID token
type Account struct {
	HomeAccountID     *string `json:"home_account_id,omitempty"`
	Environment       *string `json:"environment,omitempty"`
	Realm             *string `json:"realm,omitempty"`
	LocalAccountID    *string `json:"local_account_id,omitempty"`
	AuthorityType     *string `json:"authority_type,omitempty"`
	PreferredUsername *string `json:"username,omitempty"`
	GivenName         *string `json:"given_name,omitempty"`
	FamilyName        *string `json:"family_name,omitempty"`
	MiddleName        *string `json:"middle_name,omitempty"`
	Name              *string `json:"name,omitempty"`
	AlternativeID     *string `json:"alternative_account_id,omitempty"`
	RawClientInfo     *string `json:"client_info,omitempty"`
	additionalFields  map[string]interface{}
}

//CreateAccount creates an account
func CreateAccount(homeAccountID string,
	environment string,
	realm string,
	localAccountID string,
	authorityType string,
	preferredUsername string,
) *Account {
	a := &Account{
		HomeAccountID:     &homeAccountID,
		Environment:       &environment,
		Realm:             &realm,
		LocalAccountID:    &localAccountID,
		AuthorityType:     &authorityType,
		PreferredUsername: &preferredUsername,
	}
	return a
}

//CreateKey creates the key for storing accounts in the cache
func (acc *Account) CreateKey() string {
	keyParts := []string{
		GetStringFromPointer(acc.HomeAccountID),
		GetStringFromPointer(acc.Environment),
		GetStringFromPointer(acc.Realm),
	}
	return strings.Join(keyParts, CacheKeySeparator)
}

//GetUsername returns the username of an account
func (acc *Account) GetUsername() string {
	return GetStringFromPointer(acc.PreferredUsername)
}

//GetHomeAccountID returns the home account ID of an account
func (acc *Account) GetHomeAccountID() string {
	return GetStringFromPointer(acc.HomeAccountID)
}

//GetEnvironment returns the environment of an account
func (acc *Account) GetEnvironment() string {
	return GetStringFromPointer(acc.Environment)
}

//PopulateFromJSONMap populates an account object from a map (used for cache deserialization)
func (acc *Account) PopulateFromJSONMap(j map[string]interface{}) error {
	acc.HomeAccountID = ExtractStringPointerForCache(j, JSONHomeAccountID)
	acc.Environment = ExtractStringPointerForCache(j, JSONEnvironment)
	acc.Realm = ExtractStringPointerForCache(j, JSONRealm)
	acc.LocalAccountID = ExtractStringPointerForCache(j, JSONLocalAccountID)
	acc.AuthorityType = ExtractStringPointerForCache(j, JSONAuthorityType)
	acc.PreferredUsername = ExtractStringPointerForCache(j, JSONUsername)
	acc.AlternativeID = ExtractStringPointerForCache(j, JSONAlternativeID)
	acc.GivenName = ExtractStringPointerForCache(j, JSONGivenName)
	acc.FamilyName = ExtractStringPointerForCache(j, JSONFamilyName)
	acc.MiddleName = ExtractStringPointerForCache(j, JSONMiddleName)
	acc.Name = ExtractStringPointerForCache(j, JSONName)
	acc.RawClientInfo = ExtractStringPointerForCache(j, JSONClientInfo)
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
