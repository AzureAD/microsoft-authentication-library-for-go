package requests

import "encoding/json"

// InstanceDiscoveryResponse stuff
type InstanceDiscoveryResponse struct {
	TenantDiscoveryEndpoint string                      `json:"tenant_discovery_endpoint"`
	Metadata                []instanceDiscoveryMetadata `json:"metadata"`
}

func createInstanceDiscoveryResponse(responseData string) (*InstanceDiscoveryResponse, error) {
	discoveryResponse := &InstanceDiscoveryResponse{}
	var err = json.Unmarshal([]byte(responseData), discoveryResponse)
	if err != nil {
		return nil, err
	}
	return discoveryResponse, nil
}
