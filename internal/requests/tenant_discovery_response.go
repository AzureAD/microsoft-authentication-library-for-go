// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/json"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

// TenantDiscoveryResponse consists of the tenant endpoints from the OpenID configuration endpoint
type TenantDiscoveryResponse struct {
	// TODO(jdoak): Ask someone about why BaseResponse doesn't have a tag.
	// Either it should be encoded and we should tag it or we should tag it
	// to be omitted on export or private.
	BaseResponse          msalbase.OAuthResponseBase
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	Issuer                string `json:"issuer"`

	AdditionalFields map[string]interface{}
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
func CreateTenantDiscoveryResponse(responseCode int, responseData string) (TenantDiscoveryResponse, error) {
	resp := TenantDiscoveryResponse{}
	baseResponse, err := msalbase.CreateOAuthResponseBase(responseCode, responseData)
	if err != nil {
		return resp, err
	}

	err = json.Unmarshal([]byte(responseData), &resp)
	if err != nil {
		return resp, err
	}
	resp.BaseResponse = baseResponse
	return resp, nil
}
