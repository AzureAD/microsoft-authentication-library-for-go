// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/json"
)

// InstanceDiscoveryResponse stuff
type InstanceDiscoveryResponse struct {
	TenantDiscoveryEndpoint string                      `json:"tenant_discovery_endpoint"`
	Metadata                []InstanceDiscoveryMetadata `json:"metadata"`

	AdditionalFields map[string]interface{}
}

func CreateInstanceDiscoveryResponse(responseData string) (InstanceDiscoveryResponse, error) {
	resp := InstanceDiscoveryResponse{}
	err := json.Unmarshal([]byte(responseData), &resp)
	return resp, err
}
