// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"io/ioutil"
	"net/http"

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
func CreateTenantDiscoveryResponse(resp *http.Response) (TenantDiscoveryResponse, error) {
	tdr := TenantDiscoveryResponse{}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return tdr, err
	}
	baseResponse, err := msalbase.CreateOAuthResponseBase(resp.StatusCode, body)
	if err != nil {
		return tdr, err
	}

	err = json.Unmarshal(body, &tdr)
	if err != nil {
		return tdr, err
	}
	tdr.BaseResponse = baseResponse
	return tdr, nil
}
