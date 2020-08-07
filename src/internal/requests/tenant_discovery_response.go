// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"encoding/json"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

// TenantDiscoveryResponse consists of the tenant endpoints from the OpenID configuration endpoint
type TenantDiscoveryResponse struct {
	BaseResponse          *msalbase.OAuthResponseBase
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	Issuer                string `json:"issuer"`
}

func (r *TenantDiscoveryResponse) hasAuthorizationEndpoint() bool {
	return len(r.AuthorizationEndpoint) > 0
}

func (r *TenantDiscoveryResponse) hasTokenEndpoint() bool {
	return len(r.TokenEndpoint) > 0
}

func (r *TenantDiscoveryResponse) hasIssuer() bool {
	return len(r.Issuer) > 0
}

//CreateTenantDiscoveryResponse creates a tenant discovery response instance from an HTTP response
func CreateTenantDiscoveryResponse(responseCode int, responseData string) (*TenantDiscoveryResponse, error) {
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
