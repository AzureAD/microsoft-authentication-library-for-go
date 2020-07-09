// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"sync"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

var instanceDiscoveryCache map[string]*InstanceDiscoveryMetadata
var instanceDiscoveryCacheInitOnce sync.Once

func initInstanceDiscoveryCache() {
	instanceDiscoveryCache = make(map[string]*InstanceDiscoveryMetadata)
}

type IAadInstanceDiscovery interface {
	GetMetadataEntry(authorityInfo *msalbase.AuthorityInfo) (*InstanceDiscoveryMetadata, error)
}

type AadInstanceDiscovery struct {
	webRequestManager IWebRequestManager
}

func CreateAadInstanceDiscovery(webRequestManager IWebRequestManager) *AadInstanceDiscovery {
	instanceDiscoveryCacheInitOnce.Do(initInstanceDiscoveryCache)
	return &AadInstanceDiscovery{webRequestManager: webRequestManager}
}

func (d *AadInstanceDiscovery) doInstanceDiscoveryAndCache(authorityInfo *msalbase.AuthorityInfo) (*InstanceDiscoveryMetadata, error) {
	discoveryResponse, err := d.webRequestManager.GetAadinstanceDiscoveryResponse(authorityInfo)
	if err != nil {
		return nil, err
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

func (d *AadInstanceDiscovery) GetMetadataEntry(authorityInfo *msalbase.AuthorityInfo) (*InstanceDiscoveryMetadata, error) {
	if metadata, ok := instanceDiscoveryCache[authorityInfo.Host]; ok {
		return metadata, nil
	}
	metadata, err := d.doInstanceDiscoveryAndCache(authorityInfo)
	if err != nil {
		return nil, err
	}
	return metadata, nil
}
