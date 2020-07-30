// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"reflect"
	"testing"
)

func TestCreateAuthorityInfoFromAuthorityUri(t *testing.T) {
	authorityURI := "https://login.microsoftonline.com/common/"
	expectedAuthorityURI := &AuthorityInfo{
		Host:                  "login.microsoftonline.com",
		CanonicalAuthorityURI: authorityURI,
		AuthorityType:         MSSTS,
		UserRealmURIPrefix:    "https://login.microsoftonline.com/common/userrealm/",
		Tenant:                "common",
		ValidateAuthority:     true,
	}
	actualAuthorityURI, err := CreateAuthorityInfoFromAuthorityUri(authorityURI, true)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualAuthorityURI, expectedAuthorityURI) {
		t.Errorf("Actual authority info %+v differs from expected authority info %+v", actualAuthorityURI, expectedAuthorityURI)
	}
}
