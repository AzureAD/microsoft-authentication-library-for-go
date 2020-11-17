// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"errors"
	"testing"
)

var oauthResponse = `{}`
var oauthResponseWithError = `{"error" : "invalid request", "error_description": "missing payload content", "error_codes" : [300]}`

func TestCreateOAuthResponseBase(t *testing.T) {
	_, err := CreateOAuthResponseBase(404, []byte(oauthResponse))
	actualError := errors.New("HTTP 404")
	if err.Error() != actualError.Error() {
		t.Errorf("Actual error %v differs from expected error %v", err, actualError)
	}
	expectedErr := errors.New("invalid request: missing payload content")
	_, err = CreateOAuthResponseBase(300, []byte(oauthResponseWithError))
	if err.Error() != expectedErr.Error() {
		t.Errorf("Actual error %v differs from expected error %v", err, expectedErr)
	}
	_, err = CreateOAuthResponseBase(200, []byte(oauthResponse))
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}
