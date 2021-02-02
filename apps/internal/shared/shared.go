// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package shared

import (
	"net/http"
	"strings"
)

const (
	// CacheKeySeparator is used in creating the keys of the cache.
	CacheKeySeparator = "-"
)

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

	AdditionalFields map[string]interface{}
}

// NewAccount creates an account.
func NewAccount(homeAccountID, env, realm, localAccountID, authorityType, username string) Account {
	return Account{
		HomeAccountID:     homeAccountID,
		Environment:       env,
		Realm:             realm,
		LocalAccountID:    localAccountID,
		AuthorityType:     authorityType,
		PreferredUsername: username,
	}
}

// Key creates the key for storing accounts in the cache.
func (acc Account) Key() string {
	return strings.Join([]string{acc.HomeAccountID, acc.Environment, acc.Realm}, CacheKeySeparator)
}

<<<<<<< HEAD
//IsZero checks the zero value of account
func (acc Account) IsZero() bool {
	switch {
	case acc.HomeAccountID != "":
		return false
	case acc.Environment != "":
		return false
	case acc.Realm != "":
		return false
	case acc.LocalAccountID != "":
		return false
	case acc.AuthorityType != "":
		return false
	case acc.PreferredUsername != "":
		return false
	case acc.GivenName != "":
		return false
	case acc.FamilyName != "":
		return false
	case acc.MiddleName != "":
		return false
	case acc.Name != "":
		return false
	case acc.AlternativeID != "":
		return false
	case acc.RawClientInfo != "":
		return false
	case acc.AdditionalFields != nil:
		return false
	}
	return true
}
=======
// DefaultClient is our default shared HTTP client.
var DefaultClient = &http.Client{}
>>>>>>> 40939a8f618dff697fd15fe09444b29dea9a4033
