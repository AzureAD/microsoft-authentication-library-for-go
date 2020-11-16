// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"errors"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/json"
)

// UserRealmAccountType refers to the type of user realm.
type UserRealmAccountType int

// These are the different types of user realms.
const (
	Unknown UserRealmAccountType = iota
	Federated
	Managed
)

//UserRealm is used for the username password request to determine user type
type UserRealm struct {
	AccountType       string `json:"account_type"`
	DomainName        string `json:"domain_name"`
	CloudInstanceName string `json:"cloud_instance_name"`
	CloudAudienceURN  string `json:"cloud_audience_urn"`

	// required if accountType is Federated
	FederationProtocol    string `json:"federation_protocol"`
	FederationMetadataURL string `json:"federation_metadata_url"`

	AdditionalFields map[string]interface{}
}

func (u UserRealm) validate() error {
	switch "" {
	case u.DomainName:
		return errors.New("domain name of user realm is missing")
	case u.CloudInstanceName:
		return errors.New("cloud instance name of user realm is missing")
	case u.CloudAudienceURN:
		return errors.New("cloud Instance URN is missing")
	}

	if u.GetAccountType() == Federated {
		switch "" {
		case u.FederationProtocol:
			return errors.New("federation protocol of user realm is missing")
		case u.FederationMetadataURL:
			return errors.New("federation metadata URL of user realm is missing")
		}
	}
	return nil
}

// CreateUserRealm creates a UserRealm instance from the HTTP response
func CreateUserRealm(responseData string) (UserRealm, error) {
	u := UserRealm{}
	err := json.Unmarshal([]byte(responseData), &u)
	if err != nil {
		return u, err
	}

	return u, u.validate()
}

//GetAccountType gets the type of user account
func (u *UserRealm) GetAccountType() UserRealmAccountType {
	if u.AccountType == "Federated" {
		return Federated
	}
	if u.AccountType == "Managed" {
		return Managed
	}
	return Unknown
}
