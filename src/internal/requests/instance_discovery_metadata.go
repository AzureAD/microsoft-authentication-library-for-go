// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

type instanceDiscoveryMetadata struct {
	PreferredNetwork        string   `json:"preferred_network"`
	PreferredCache          string   `json:"preferred_cache"`
	TenantDiscoveryEndpoint string   `json:"tenant_discovery_endpoint"`
	Aliases                 []string `json:"aliases"`
}

func createInstanceDiscoveryMetadata(preferredNetwork string, preferredCache string) *instanceDiscoveryMetadata {
	return &instanceDiscoveryMetadata{
		PreferredNetwork: preferredNetwork,
		PreferredCache:   preferredCache,
		Aliases:          []string{},
	}
}
