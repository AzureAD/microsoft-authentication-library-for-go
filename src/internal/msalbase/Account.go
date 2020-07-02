// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import "strings"

type Account struct {
	HomeAccountID     string
	Environment       string
	Realm             string
	localAccountID    string
	authorityType     AuthorityType
	preferredUsername string
	GivenName         string
	FamilyName        string
	MiddleName        string
	Name              string
	AlternativeID     string
	RawClientInfo     string
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
		localAccountID:    localAccountID,
		authorityType:     authorityType,
		preferredUsername: preferredUsername,
	}
	return a
}

func (acc *Account) CreateKey() string {
	keyParts := []string{acc.HomeAccountID, acc.Environment, acc.Realm}
	return strings.Join(keyParts, CacheKeySeparator)
}

func (acc *Account) GetUsername() string {
	return acc.preferredUsername
}

func (acc *Account) GetHomeAccountID() string {
	return acc.HomeAccountID
}

func (acc *Account) GetEnvironment() string {
	return acc.Environment
}
