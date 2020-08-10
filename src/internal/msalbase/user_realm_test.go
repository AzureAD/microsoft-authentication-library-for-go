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
