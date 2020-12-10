// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"context"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

// TODO(jdoak): Remove this.
var instanceDiscoveryCache = map[string]InstanceDiscoveryMetadata{}

type AadInstanceDiscovery struct {
	webRequestManager WebRequestManager
}

func CreateAadInstanceDiscovery(webRequestManager WebRequestManager) *AadInstanceDiscovery {
	return &AadInstanceDiscovery{webRequestManager: webRequestManager}
}

func (d *AadInstanceDiscovery) doInstanceDiscoveryAndCache(ctx context.Context, authorityInfo msalbase.AuthorityInfo) (InstanceDiscoveryMetadata, error) {
	discoveryResponse, err := d.webRequestManager.GetAadinstanceDiscoveryResponse(ctx, authorityInfo)
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

func (d *AadInstanceDiscovery) GetMetadataEntry(ctx context.Context, authorityInfo msalbase.AuthorityInfo) (InstanceDiscoveryMetadata, error) {
	if metadata, ok := instanceDiscoveryCache[authorityInfo.Host]; ok {
		return metadata, nil
	}
	metadata, err := d.doInstanceDiscoveryAndCache(ctx, authorityInfo)
	if err != nil {
		return InstanceDiscoveryMetadata{}, err
	}
	return metadata, nil
}
