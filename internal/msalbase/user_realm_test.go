// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"testing"

	"github.com/kylelemons/godebug/pretty"
)

var testRealm = `{"account_type" : "Federated",
					"domain_name" : "domain",
					"cloud_instance_name" : "cloud",
					"cloud_audience_urn" : "urn",
					"federation_protocol" : "fed_prot",
					"federation_metadata_url" : "fed_meta"}`

func TestCreateUserRealm(t *testing.T) {
	// TODO(jdoak): make these maps that we just json.Marshal before we
	// call CreateUserRealm().
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

	tests := []struct {
		desc  string
		input string
		want  UserRealm
		err   bool
	}{
		{
			desc:  "success",
			input: testRealm,
			want: UserRealm{
				AccountType:           "Federated",
				DomainName:            "domain",
				CloudInstanceName:     "cloud",
				CloudAudienceURN:      "urn",
				FederationProtocol:    "fed_prot",
				FederationMetadataURL: "fed_meta",
			},
		},
		{desc: "error: Fed Protocol Realm", input: fedProtRealm, err: true},
		{desc: "error: Fed Meta Realm", input: fedMetaRealm, err: true},
		{desc: "error: Domain Realm", input: domainRealm, err: true},
		{desc: "error: Cloud Name Realm", input: cloudNameRealm, err: true},
		{desc: "error: Cloud URN Realm", input: cloudURNRealm, err: true},
	}
	for _, test := range tests {
		got, err := CreateUserRealm(test.input)
		switch {
		case err == nil && test.err:
			t.Errorf("TestCreateUserRealm(%s): got err == nil, want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestCreateUserRealm(%s): got err == %s, want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if diff := pretty.Compare(test.want, got); diff != "" {
			t.Errorf("TestCreateUserRealm(%s): -want/+got:\n%s", test.desc, diff)
		}
	}
}
