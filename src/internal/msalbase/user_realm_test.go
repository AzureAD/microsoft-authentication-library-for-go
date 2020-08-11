// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"errors"
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
	type testData struct {
		input string
		err   error
		realm *UserRealm
	}
	expectedUserRealm := &UserRealm{
		AccountType:           "Federated",
		DomainName:            "domain",
		CloudInstanceName:     "cloud",
		CloudAudienceURN:      "urn",
		FederationProtocol:    "fed_prot",
		FederationMetadataURL: "fed_meta",
	}
	fedProtRealm := `{"account_type" : "Federated",
				"domain_name" : "domain",
				"cloud_instance_name" : "cloud",
				"cloud_audience_urn" : "urn",
				"federation_metadata_url" : "fed_meta"}`
	fedMetaRealm := `{"account_type" : "Federated",
				"domain_name" : "domain",
				"cloud_instance_name" : "cloud",
				"cloud_audience_urn" : "urn",
				"federation_protocol" : "fed_prot"}`
	domainRealm := `{"account_type" : "Managed",
				"cloud_instance_name" : "cloud",
				"cloud_audience_urn" : "urn"}`
	cloudNameRealm := `{"account_type" : "Managed",
						"domain_name" : "domain",
						"cloud_audience_urn" : "urn"}`
	cloudURNRealm := `{"account_type" : "Managed",
						"domain_name" : "domain",
						"cloud_instance_name" : "cloud"}`
	tests := []testData{
		{input: testRealm, err: nil, realm: expectedUserRealm},
		{input: fedProtRealm, err: errors.New("federation protocol of user realm is missing"), realm: nil},
		{input: fedMetaRealm, err: errors.New("federation metadata URL of user realm is missing"), realm: nil},
		{input: domainRealm, err: errors.New("domain name of user realm is missing"), realm: nil},
		{input: cloudNameRealm, err: errors.New("cloud instance name of user realm is missing"), realm: nil},
		{input: cloudURNRealm, err: errors.New("cloud Instance URN is missing"), realm: nil},
	}
	for _, test := range tests {
		actualRealm, err := CreateUserRealm(test.input)
		if err != test.err {
			if err == nil || !reflect.DeepEqual(err.Error(), test.err.Error()) {
				t.Errorf("Actual error %v differs from expected error %v", err, test.err)
			}
		}
		if !reflect.DeepEqual(actualRealm, test.realm) {
			t.Errorf("Actual user realm %+v differs from expected user realm %+v", actualRealm, test.realm)
		}
	}
}
