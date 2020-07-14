// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import "strings"

type Account struct {
	HomeAccountID     string
	Environment       string
	Realm             string
	LocalAccountID    string
	AuthorityType     AuthorityType
	PreferredUsername string
	GivenName         string
	FamilyName        string
	MiddleName        string
	Name              string
	AlternativeID     string
	RawClientInfo     string
	AdditionalFields  map[string]interface{}
}

func CreateAccount(homeAccountID string,
	environment string,
	realm string,
	localAccountID string,
	authorityType AuthorityType,
	preferredUsername string,
) *Account {
	a := &Account{
		HomeAccountID:     homeAccountID,
		Environment:       environment,
		Realm:             realm,
		LocalAccountID:    localAccountID,
		AuthorityType:     authorityType,
		PreferredUsername: preferredUsername,
	}
	return a
}

func (acc *Account) CreateKey() string {
	keyParts := []string{acc.HomeAccountID, acc.Environment, acc.Realm}
	return strings.Join(keyParts, CacheKeySeparator)
}

func (acc *Account) GetUsername() string {
	return acc.PreferredUsername
}

func (acc *Account) GetHomeAccountID() string {
	return acc.HomeAccountID
}

func (acc *Account) GetEnvironment() string {
	return acc.Environment
}

func (acc *Account) PopulateFromJSONMap(j map[string]interface{}) error {
	acc.HomeAccountID = ExtractExistingOrEmptyString(j, "home_account_id")
	acc.Environment = ExtractExistingOrEmptyString(j, "environment")
	acc.Realm = ExtractExistingOrEmptyString(j, "realm")
	acc.LocalAccountID = ExtractExistingOrEmptyString(j, "local_account_id")
	acc.AuthorityType = ToAuthorityType(ExtractExistingOrEmptyString(j, "authority_type"))
	acc.PreferredUsername = ExtractExistingOrEmptyString(j, "username")
	acc.AlternativeID = ExtractExistingOrEmptyString(j, "alternative_account_id")
	acc.GivenName = ExtractExistingOrEmptyString(j, "given_name")
	acc.FamilyName = ExtractExistingOrEmptyString(j, "family_name")
	acc.MiddleName = ExtractExistingOrEmptyString(j, "middle_name")
	acc.Name = ExtractExistingOrEmptyString(j, "name")
	acc.RawClientInfo = ExtractExistingOrEmptyString(j, "client_info")
	acc.AdditionalFields = j
	return nil
}

func (acc *Account) ConvertToJSONMap() (map[string]interface{}, error) {
	jsonMap := acc.AdditionalFields
	jsonMap["home_account_id"] = acc.HomeAccountID
	jsonMap["environment"] = acc.Environment
	jsonMap["realm"] = acc.Realm
	jsonMap["local_account_id"] = acc.LocalAccountID
	jsonMap["authority_type"] = acc.AuthorityType.ToString()
	jsonMap["username"] = acc.PreferredUsername
	if acc.AlternativeID != "" {
		jsonMap["alternative_account_id"] = acc.AlternativeID
	}
	if acc.GivenName != "" {
		jsonMap["given_name"] = acc.GivenName
	}
	if acc.FamilyName != "" {
		jsonMap["family_name"] = acc.FamilyName
	}
	if acc.MiddleName != "" {
		jsonMap["middle_name"] = acc.MiddleName
	}
	if acc.Name != "" {
		jsonMap["name"] = acc.Name
	}
	if acc.RawClientInfo != "" {
		jsonMap["client_info"] = acc.RawClientInfo
	}
	return jsonMap, nil
}
