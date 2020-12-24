// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
)

type jsonCaller interface {
	JSONCall(ctx context.Context, endpoint string, headers http.Header, qv url.Values, body, resp interface{}) error
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

func (c Client) GetTenantDiscoveryResponse(ctx context.Context, openIDConfigurationEndpoint string) (requests.TenantDiscoveryResponse, error) {
	resp := requests.TenantDiscoveryResponse{}
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

func (c Client) GetAadinstanceDiscoveryResponse(ctx context.Context, authorityInfo msalbase.AuthorityInfo) (requests.InstanceDiscoveryResponse, error) {
	qv := url.Values{}
	qv.Set("api-version", "1.1")
	qv.Set("authorization_endpoint", fmt.Sprintf(msalbase.AuthorizationEndpoint, authorityInfo.Host, authorityInfo.Tenant))

	discoveryHost := msalbase.DefaultHost
	if requests.IsInTrustedHostList(authorityInfo.Host) {
		discoveryHost = authorityInfo.Host
	}

	endpoint := fmt.Sprintf(msalbase.InstanceDiscoveryEndpoint, discoveryHost)

	resp := requests.InstanceDiscoveryResponse{}
	err := c.Comm.JSONCall(ctx, endpoint, http.Header{}, qv, nil, &resp)
	return resp, err
}
