// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

type InstanceDiscoveryMetadata struct {
	PreferredNetwork        string   `json:"preferred_network"`
	PreferredCache          string   `json:"preferred_cache"`
	TenantDiscoveryEndpoint string   `json:"tenant_discovery_endpoint"`
	Aliases                 []string `json:"aliases"`

	AdditionalFields map[string]interface{}
}

func createInstanceDiscoveryMetadata(preferredNetwork string, preferredCache string) InstanceDiscoveryMetadata {
	return InstanceDiscoveryMetadata{
		PreferredNetwork: preferredNetwork,
		PreferredCache:   preferredCache,
		Aliases:          []string{},
	}
}
