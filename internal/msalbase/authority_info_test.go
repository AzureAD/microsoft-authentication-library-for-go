// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"testing"

	"github.com/kylelemons/godebug/pretty"
)

func TestCreateAuthorityInfoFromAuthorityUri(t *testing.T) {
	const authorityURI = "https://login.microsoftonline.com/common/"

	want := AuthorityInfo{
		Host:                  "login.microsoftonline.com",
		CanonicalAuthorityURI: authorityURI,
		AuthorityType:         MSSTS,
		UserRealmURIPrefix:    "https://login.microsoftonline.com/common/userrealm/",
		Tenant:                "common",
		ValidateAuthority:     true,
	}
	got, err := CreateAuthorityInfoFromAuthorityURI(authorityURI, true)
	if err != nil {
		t.Fatalf("TestCreateAuthorityInfoFromAuthorityUri: got err == %s, want err == nil", err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestCreateAuthorityInfoFromAuthorityUri: -want/+got:\n%s", diff)
	}
}
