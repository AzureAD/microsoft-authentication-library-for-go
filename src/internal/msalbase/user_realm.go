// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"encoding/json"
	"errors"
)

type UserRealmAccountType int

const (
	Unknown UserRealmAccountType = iota
	Federated
	Managed
)

type UserRealm struct {
	AccountType       string `json:"account_type"`
	DomainName        string `json:"domain_name"`
	CloudInstanceName string `json:"cloud_instance_name"`
	CloudAudienceURN  string `json:"cloud_audience_urn"`

	// required if accountType is Federated
	FederationProtocol    string `json:"federation_protocol"`
	FederationMetadataURL string `json:"federation_metadata_url"`
}

// CreateUserRealm stuff
func CreateUserRealm(responseData string) (*UserRealm, error) {
	userRealm := &UserRealm{}
	err := json.Unmarshal([]byte(responseData), userRealm)
	if err != nil {
		return nil, err
	}
	if userRealm.GetAccountType() == Federated {
		if userRealm.FederationProtocol == "" {
			return nil, errors.New("Federation protocol of user realm is missing")
		}
		if userRealm.FederationMetadataURL == "" {
			return nil, errors.New("Federation metadata URL of user realm is missing")
		}
	}
	if userRealm.DomainName == "" {
		return nil, errors.New("Domain name of user realm is missing")
	}
	if userRealm.CloudInstanceName == "" {
		return nil, errors.New("Cloud instance name of user realm is missing")
	}
	if userRealm.CloudAudienceURN == "" {
		return nil, errors.New("Cloud Instance URN is missing")
	}
	return userRealm, nil
}

func (u *UserRealm) GetAccountType() UserRealmAccountType {
	if u.AccountType == "Federated" {
		return Federated
	}
	if u.AccountType == "Managed" {
		return Managed
	}
	return Unknown
}
