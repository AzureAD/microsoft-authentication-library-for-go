// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"reflect"
	"testing"
)

func TestAuthorityTypeToString(t *testing.T) {
	if !reflect.DeepEqual(AuthorityTypeAad.ToString(), "MSSTS") {
		t.Errorf("Actual authority type %s differs from expected authority type %s",
			AuthorityTypeAad.ToString(), "MSSTS")
	}
	if !reflect.DeepEqual(AuthorityTypeAdfs.ToString(), "ADFS") {
		t.Errorf("Actual authority type %s differs from expected authority type %s",
			AuthorityTypeAdfs.ToString(), "ADFS")
	}
	if !reflect.DeepEqual(AuthorityTypeNone.ToString(), "") {
		t.Errorf("Actual authority type %s differs from expected authority type %s",
			AuthorityTypeNone.ToString(), "")
	}
}
