// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

type CloudEnvironmentInfo struct {
	preferredNetwork string
	preferredCache   string
	aliases          map[string]bool
}

func CreateCloudEnvironmentInfo(preferredNetwork string, preferredCache string, aliases []string) *CloudEnvironmentInfo {
	aliasMap := map[string]bool{}
	for _, a := range aliases {
		aliasMap[a] = true
	}

	c := &CloudEnvironmentInfo{preferredNetwork, preferredCache, aliasMap}
	return c
}

func (c *CloudEnvironmentInfo) GetPreferredNetwork() string {
	return c.preferredNetwork
}

func (c *CloudEnvironmentInfo) GetPreferredCache() string {
	return c.preferredCache
}

func (c *CloudEnvironmentInfo) GetAliases() map[string]bool {
	return c.aliases
}
