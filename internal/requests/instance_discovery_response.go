// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"io/ioutil"
	"net/http"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/json"
)

// InstanceDiscoveryResponse stuff
type InstanceDiscoveryResponse struct {
	TenantDiscoveryEndpoint string                      `json:"tenant_discovery_endpoint"`
	Metadata                []InstanceDiscoveryMetadata `json:"metadata"`

	AdditionalFields map[string]interface{}
}

func CreateInstanceDiscoveryResponse(resp *http.Response) (InstanceDiscoveryResponse, error) {
	idr := InstanceDiscoveryResponse{}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return idr, err
	}
	return idr, json.Unmarshal(body, &idr)
}
