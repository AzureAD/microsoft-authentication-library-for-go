// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/apps/internal/msalbase"
)

type jsonCaller interface {
	JSONCall(ctx context.Context, endpoint string, headers http.Header, qv url.Values, body, resp interface{}) error
}

// TenantDiscoveryResponse is the tenant endpoints from the OpenID configuration endpoint.
type TenantDiscoveryResponse struct {
	msalbase.OAuthResponseBase

	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	Issuer                string `json:"issuer"`

	AdditionalFields map[string]interface{}
}

// Validate validates that the response had the correct values required.
func (r *TenantDiscoveryResponse) Validate() error {
	switch "" {
	case r.AuthorizationEndpoint:
		return errors.New("TenantDiscoveryResponse: authorize endpoint was not found in the openid configuration")
	case r.TokenEndpoint:
		return errors.New("TenantDiscoveryResponse: token endpoint was not found in the openid configuration")
	case r.Issuer:
		return errors.New("TenantDiscoveryResponse: issuer was not found in the openid configuration")
	}
	return nil
}

func (r *TenantDiscoveryResponse) HasAuthorizationEndpoint() bool {
	return len(r.AuthorizationEndpoint) > 0
}

func (r *TenantDiscoveryResponse) HasTokenEndpoint() bool {
	return len(r.TokenEndpoint) > 0
}

func (r *TenantDiscoveryResponse) HasIssuer() bool {
	return len(r.Issuer) > 0
}

type InstanceDiscoveryMetadata struct {
	PreferredNetwork        string   `json:"preferred_network"`
	PreferredCache          string   `json:"preferred_cache"`
	TenantDiscoveryEndpoint string   `json:"tenant_discovery_endpoint"`
	Aliases                 []string `json:"aliases"`

	AdditionalFields map[string]interface{}
}

type InstanceDiscoveryResponse struct {
	TenantDiscoveryEndpoint string                      `json:"tenant_discovery_endpoint"`
	Metadata                []InstanceDiscoveryMetadata `json:"metadata"`

	AdditionalFields map[string]interface{}
}

// Client represents the REST calls to authority backends.
type Client struct {
	// Comm provides the HTTP transport client.
	Comm jsonCaller // *comm.Client
}

func (c Client) GetUserRealm(ctx context.Context, authParameters msalbase.AuthParametersInternal) (msalbase.UserRealm, error) {
	endpoint := authParameters.Endpoints.GetUserRealmEndpoint(authParameters.Username)

	resp := msalbase.UserRealm{}
	err := c.Comm.JSONCall(
		ctx,
		endpoint,
		// TODO(jdoak): not thrilled about this, because all calls should have this but
		// only calls with authParameters is using this.
		http.Header{"client-request-id": []string{authParameters.CorrelationID}},
		nil,
		nil,
		&resp,
	)
	return resp, err
}

func (c Client) GetTenantDiscoveryResponse(ctx context.Context, openIDConfigurationEndpoint string) (TenantDiscoveryResponse, error) {
	resp := TenantDiscoveryResponse{}
	err := c.Comm.JSONCall(
		ctx,
		openIDConfigurationEndpoint,
		http.Header{},
		nil,
		nil,
		&resp,
	)

	return resp, err
}

func (c Client) GetAadinstanceDiscoveryResponse(ctx context.Context, authorityInfo msalbase.AuthorityInfo) (InstanceDiscoveryResponse, error) {
	qv := url.Values{}
	qv.Set("api-version", "1.1")
	qv.Set("authorization_endpoint", fmt.Sprintf(msalbase.AuthorizationEndpoint, authorityInfo.Host, authorityInfo.Tenant))

	discoveryHost := msalbase.DefaultHost
	if msalbase.TrustedHost(authorityInfo.Host) {
		discoveryHost = authorityInfo.Host
	}

	endpoint := fmt.Sprintf(msalbase.InstanceDiscoveryEndpoint, discoveryHost)

	resp := InstanceDiscoveryResponse{}
	err := c.Comm.JSONCall(ctx, endpoint, http.Header{}, qv, nil, &resp)
	return resp, err
}
