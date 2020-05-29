// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"encoding/json"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

// TenantDiscoveryResponse stuff
type TenantDiscoveryResponse struct {
	BaseResponse *msalbase.OAuthResponseBase

	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	Issuer                string `json:"issuer"`
}

// HasAuthorizationEndpoint stuff
func (r *TenantDiscoveryResponse) HasAuthorizationEndpoint() bool {
	return len(r.AuthorizationEndpoint) > 0
}

// HasTokenEndpoint stuff
func (r *TenantDiscoveryResponse) HasTokenEndpoint() bool {
	return len(r.TokenEndpoint) > 0
}

// HasIssuer stuff
func (r *TenantDiscoveryResponse) HasIssuer() bool {
	return len(r.Issuer) > 0
}

func createTenantDiscoveryResponse(responseCode int, responseData string) (*TenantDiscoveryResponse, error) {
	baseResponse, err := msalbase.CreateOAuthResponseBase(responseCode, responseData)
	if err != nil {
		return nil, err
	}

	discoveryResponse := &TenantDiscoveryResponse{}
	err = json.Unmarshal([]byte(responseData), discoveryResponse)
	if err != nil {
		return nil, err
	}

	discoveryResponse.BaseResponse = baseResponse

	return discoveryResponse, nil
}
