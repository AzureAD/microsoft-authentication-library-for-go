// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"encoding/json"

	log "github.com/sirupsen/logrus"
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
	CloudInstanceNmae string `json:"cloud_instance_name"`
	CloudAudienceURN  string `json:"cloud_audience_urn"`

	// required if accountType is Federated
	FederationProtocol    string `json:"federation_protocol"`
	FederationMetadataURL string `json:"federation_metadata_url"`
}

// CreateUserRealm stuff
func CreateUserRealm(responseData string) (*UserRealm, error) {
	log.Trace(responseData)
	userRealm := &UserRealm{}
	var err = json.Unmarshal([]byte(responseData), userRealm)
	if err != nil {
		return nil, err
	}

	if userRealm.GetAccountType() == Federated {
		// todo: assert federationProtocol and federationMetadataURL are set/valid/non-null
	}

	// todo: assert domainName, cloudInstanceName, cloudInstanceUrn are set/valid/non-null

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

func (u *UserRealm) GetFederationMetadataURL() string {
	return u.FederationMetadataURL
}

func (u *UserRealm) GetCloudAudienceURN() string {
	return u.CloudAudienceURN
}
