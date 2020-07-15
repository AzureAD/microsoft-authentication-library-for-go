// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"encoding/json"
	"strings"
)

type Account struct {
	HomeAccountID       *string `json:"home_account_id,omitempty"`
	Environment         *string `json:"environment,omitempty"`
	Realm               *string `json:"realm,omitempty"`
	LocalAccountID      *string `json:"local_account_id,omitempty"`
	AuthorityTypeString *string `json:"authority_type,omitempty"`
	authorityType       AuthorityType
	PreferredUsername   *string `json:"username,omitempty"`
	GivenName           *string `json:"given_name,omitempty"`
	FamilyName          *string `json:"family_name,omitempty"`
	MiddleName          *string `json:"middle_name,omitempty"`
	Name                *string `json:"name,omitempty"`
	AlternativeID       *string `json:"alternative_account_id,omitempty"`
	RawClientInfo       *string `json:"client_info,omitempty"`
	additionalFields    map[string]interface{}
}

func CreateAccount(homeAccountID string,
	environment string,
	realm string,
	localAccountID string,
	authorityType AuthorityType,
	preferredUsername string,
) *Account {
	authType := authorityType.ToString()
	a := &Account{
		HomeAccountID:       &homeAccountID,
		Environment:         &environment,
		Realm:               &realm,
		LocalAccountID:      &localAccountID,
		authorityType:       authorityType,
		AuthorityTypeString: &authType,
		PreferredUsername:   &preferredUsername,
	}
	return a
}

func (acc *Account) CreateKey() string {
	keyParts := []string{*acc.HomeAccountID, *acc.Environment, *acc.Realm}
	return strings.Join(keyParts, CacheKeySeparator)
}

func (acc *Account) GetUsername() string {
	if acc.PreferredUsername == nil {
		return ""
	}
	return *acc.PreferredUsername
}

func (acc *Account) GetHomeAccountID() string {
	if acc.HomeAccountID == nil {
		return ""
	}
	return *acc.HomeAccountID
}

func (acc *Account) GetEnvironment() string {
	if acc.Environment == nil {
		return ""
	}
	return *acc.Environment
}

func (acc *Account) PopulateFromJSONMap(j map[string]interface{}) error {
	acc.HomeAccountID = ExtractStringPointerForCache(j, "home_account_id")
	acc.Environment = ExtractStringPointerForCache(j, "environment")
	acc.Realm = ExtractStringPointerForCache(j, "realm")
	acc.LocalAccountID = ExtractStringPointerForCache(j, "local_account_id")
	acc.AuthorityTypeString = ExtractStringPointerForCache(j, "authority_type")
	if acc.AuthorityTypeString != nil {
		acc.authorityType = ToAuthorityType(*acc.AuthorityTypeString)
	}
	acc.PreferredUsername = ExtractStringPointerForCache(j, "username")
	acc.AlternativeID = ExtractStringPointerForCache(j, "alternative_account_id")
	acc.GivenName = ExtractStringPointerForCache(j, "given_name")
	acc.FamilyName = ExtractStringPointerForCache(j, "family_name")
	acc.MiddleName = ExtractStringPointerForCache(j, "middle_name")
	acc.Name = ExtractStringPointerForCache(j, "name")
	acc.RawClientInfo = ExtractStringPointerForCache(j, "client_info")
	acc.additionalFields = j
	return nil
}

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
