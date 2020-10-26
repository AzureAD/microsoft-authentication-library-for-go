// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"reflect"
	"testing"
)

func TestCreateTenantDiscoveryResponse(t *testing.T) {
	tdrText := `{"authorization_endpoint": "auth", "token_endpoint": "token", "issuer": "iss"}`
	expectedTDR := &TenantDiscoveryResponse{
		AuthorizationEndpoint: "auth",
		TokenEndpoint:         "token",
		Issuer:                "iss",
	}
	actualTDR, err := CreateTenantDiscoveryResponse(200, tdrText)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(expectedTDR.AuthorizationEndpoint, actualTDR.AuthorizationEndpoint) &&
		!reflect.DeepEqual(expectedTDR.TokenEndpoint, actualTDR.TokenEndpoint) &&
		!reflect.DeepEqual(expectedTDR.Issuer, actualTDR.Issuer) {
		t.Errorf("Actual tenant discovery response %+v differs from expected tenant discovery response %+v", actualTDR, expectedTDR)
	}
}
