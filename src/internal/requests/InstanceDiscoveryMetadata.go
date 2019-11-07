package requests

type instanceDiscoveryMetadata struct {
	PreferredNetwork        string   `json:"preferred_network"`
	PreferredCache          string   `json:"preferred_cache"`
	TenantDiscoveryEndpoint string   `json:"tenant_discovery_endpoint"`
	Aliases                 []string `json:"aliases"`
}

func createInstanceDiscoveryMetadata(authorityHost string, tenantDiscoveryEndpoint string) *instanceDiscoveryMetadata {
	return &instanceDiscoveryMetadata{authorityHost, authorityHost, tenantDiscoveryEndpoint, []string{}}
}
