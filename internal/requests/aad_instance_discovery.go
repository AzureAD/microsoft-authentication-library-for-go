// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

var instanceDiscoveryCache = map[string]InstanceDiscoveryMetadata{}

type AadInstanceDiscovery struct {
	webRequestManager WebRequestManager
}

func CreateAadInstanceDiscovery(webRequestManager WebRequestManager) *AadInstanceDiscovery {
	return &AadInstanceDiscovery{webRequestManager: webRequestManager}
}

func (d *AadInstanceDiscovery) doInstanceDiscoveryAndCache(authorityInfo msalbase.AuthorityInfo) (InstanceDiscoveryMetadata, error) {
	discoveryResponse, err := d.webRequestManager.GetAadinstanceDiscoveryResponse(authorityInfo)
	if err != nil {
		return InstanceDiscoveryMetadata{}, err
	}

	for _, metadataEntry := range discoveryResponse.Metadata {
		metadataEntry.TenantDiscoveryEndpoint = discoveryResponse.TenantDiscoveryEndpoint
		for _, aliasedAuthority := range metadataEntry.Aliases {
			instanceDiscoveryCache[aliasedAuthority] = metadataEntry
		}
	}
	if _, ok := instanceDiscoveryCache[authorityInfo.Host]; !ok {
		instanceDiscoveryCache[authorityInfo.Host] = createInstanceDiscoveryMetadata(authorityInfo.Host, authorityInfo.Host)
	}
	return instanceDiscoveryCache[authorityInfo.Host], nil
}

func (d *AadInstanceDiscovery) GetMetadataEntry(authorityInfo msalbase.AuthorityInfo) (InstanceDiscoveryMetadata, error) {
	if metadata, ok := instanceDiscoveryCache[authorityInfo.Host]; ok {
		return metadata, nil
	}
	metadata, err := d.doInstanceDiscoveryAndCache(authorityInfo)
	if err != nil {
		return InstanceDiscoveryMetadata{}, err
	}
	return metadata, nil
}
