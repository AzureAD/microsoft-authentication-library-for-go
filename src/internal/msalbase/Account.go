// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

type Account struct {
	homeAccountID        string
	environment          string
	realm                string
	localAccountID       string
	authorityType        AuthorityType
	preferredUsername    string
	GivenName            string
	FamilyName           string
	MiddleName           string
	Name                 string
	AlternativeID        string
	RawClientInfo        string
	additionalFieldsJSON string
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
		realm:             realm,
		localAccountID:    localAccountID,
		authorityType:     authorityType,
		preferredUsername: preferredUsername,
	}
	return a
}
