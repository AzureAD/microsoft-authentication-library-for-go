// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"reflect"
	"testing"
)

var testRealm = `{"account_type" : "Federated",
					"domain_name" : "domain",
					"cloud_instance_name" : "cloud",
					"cloud_audience_urn" : "urn",
					"federation_protocol" : "fed_prot",
					"federation_metadata_url" : "fed_meta"}`

func TestCreateUserRealm(t *testing.T) {
	expectedUserRealm := &UserRealm{
		AccountType:           "Federated",
		DomainName:            "domain",
		CloudInstanceName:     "cloud",
		CloudAudienceURN:      "urn",
		FederationProtocol:    "fed_prot",
		FederationMetadataURL: "fed_meta",
	}
	actualRealm, err := CreateUserRealm(testRealm)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualRealm, expectedUserRealm) {
		t.Errorf("Actual user realm %+v differs from expected user realm %+v", actualRealm, expectedUserRealm)
	}
}

func TestCreateUserRealmWithErrors(t *testing.T) {
	realm := `{"account_type" : "Federated",
				"domain_name" : "domain",
				"cloud_instance_name" : "cloud",
				"cloud_audience_urn" : "urn",
				"federation_metadata_url" : "fed_meta"}`
	_, err := CreateUserRealm(realm)
	if !reflect.DeepEqual(err.Error(), "federation protocol of user realm is missing") {
		t.Errorf("Actual error %s differs from expected error %s",
			err.Error(), "federation protocol of user realm is missing")
	}
	realm = `{"account_type" : "Federated",
				"domain_name" : "domain",
				"cloud_instance_name" : "cloud",
				"cloud_audience_urn" : "urn",
				"federation_protocol" : "fed_prot"}`
	_, err = CreateUserRealm(realm)
	if !reflect.DeepEqual(err.Error(), "federation metadata URL of user realm is missing") {
		t.Errorf("Actual error %s differs from expected error %s",
			err.Error(), "federation metadata URL of user realm is missing")
	}
	realm = `{"account_type" : "Managed",
				"cloud_instance_name" : "cloud",
				"cloud_audience_urn" : "urn"}`
	_, err = CreateUserRealm(realm)
	if !reflect.DeepEqual(err.Error(), "domain name of user realm is missing") {
		t.Errorf("Actual error %s differs from expected error %s",
			err.Error(), "domain name of user realm is missing")
	}
	realm = `{"account_type" : "Managed",
				"domain_name" : "domain",
				"cloud_audience_urn" : "urn"}`
	_, err = CreateUserRealm(realm)
	if !reflect.DeepEqual(err.Error(), "cloud instance name of user realm is missing") {
		t.Errorf("Actual error %s differs from expected error %s",
			err.Error(), "cloud instance name of user realm is missing")
	}
	realm = `{"account_type" : "Managed",
				"domain_name" : "domain",
				"cloud_instance_name" : "cloud"}`
	_, err = CreateUserRealm(realm)
	if !reflect.DeepEqual(err.Error(), "cloud Instance URN is missing") {
		t.Errorf("Actual error %s differs from expected error %s",
			err.Error(), "cloud Instance URN is missing")
	}
}
