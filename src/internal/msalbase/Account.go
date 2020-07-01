// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import "strings"

type Account struct {
	homeAccountID     string
	environment       string
	realm             string
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
		homeAccountID:     homeAccountID,
		environment:       environment,
		realm:             realm,
		localAccountID:    localAccountID,
		authorityType:     authorityType,
		preferredUsername: preferredUsername,
	}
	return a
}

func (acc *Account) CreateKey() string {
	keyParts := []string{acc.homeAccountID, acc.environment, acc.realm}
	return strings.Join(keyParts, CacheKeySeparator)
}

func (acc *Account) GetUsername() string {
	return acc.preferredUsername
}

func (acc *Account) GetHomeAccountID() string {
	return acc.homeAccountID
}

func (acc *Account) GetEnvironment() string {
	return acc.environment
}
