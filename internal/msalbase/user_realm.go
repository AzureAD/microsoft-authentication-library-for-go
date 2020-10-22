// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"encoding/json"
	"errors"
)

//UserRealmAccountType refers to the type of user realm
type UserRealmAccountType int

//These are the different types of user realms
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
}

// CreateUserRealm creates a UserRealm instance from the HTTP response
func CreateUserRealm(responseData string) (*UserRealm, error) {
	userRealm := &UserRealm{}
	err := json.Unmarshal([]byte(responseData), userRealm)
	if err != nil {
		return nil, err
	}
	if userRealm.GetAccountType() == Federated {
		if userRealm.FederationProtocol == "" {
			return nil, errors.New("federation protocol of user realm is missing")
		}
		if userRealm.FederationMetadataURL == "" {
			return nil, errors.New("federation metadata URL of user realm is missing")
		}
	}
	if userRealm.DomainName == "" {
		return nil, errors.New("domain name of user realm is missing")
	}
	if userRealm.CloudInstanceName == "" {
		return nil, errors.New("cloud instance name of user realm is missing")
	}
	if userRealm.CloudAudienceURN == "" {
		return nil, errors.New("cloud Instance URN is missing")
	}
	return userRealm, nil
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
