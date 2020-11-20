// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"context"
	"fmt"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

type openIDConfigurationEndpointManager interface {
	getOpenIDConfigurationEndpoint(ctx context.Context, authorityInfo msalbase.AuthorityInfo, userPrincipalName string) (string, error)
}

type aadOpenIDConfigurationEndpointManager struct {
	aadInstanceDiscovery *AadInstanceDiscovery
}

func createAadOpenIDConfigurationEndpointManager(aadInstanceDiscovery *AadInstanceDiscovery) openIDConfigurationEndpointManager {
	m := &aadOpenIDConfigurationEndpointManager{aadInstanceDiscovery}
	return m
}

var aadTrustedHostList = map[string]bool{
	"login.windows.net":            true, // Microsoft Azure Worldwide - Used in validation scenarios where host is not this list
	"login.chinacloudapi.cn":       true, // Microsoft Azure China
	"login.microsoftonline.de":     true, // Microsoft Azure Blackforest
	"login-us.microsoftonline.com": true, // Microsoft Azure US Government - Legacy
	"login.microsoftonline.us":     true, // Microsoft Azure US Government
	"login.microsoftonline.com":    true, // Microsoft Azure Worldwide
	"login.cloudgovapi.us":         true, // Microsoft Azure US Government
}

//IsInTrustedHostList checks if an AAD host is trusted/valid
func IsInTrustedHostList(host string) bool {
	if _, ok := aadTrustedHostList[host]; ok {
		return true
	}
	return false
}

func (m *aadOpenIDConfigurationEndpointManager) getOpenIDConfigurationEndpoint(ctx context.Context, authorityInfo msalbase.AuthorityInfo, userPrincipalName string) (string, error) {
	if authorityInfo.ValidateAuthority && !IsInTrustedHostList(authorityInfo.Host) {
		discoveryResponse, err := m.aadInstanceDiscovery.GetMetadataEntry(ctx, authorityInfo)
		if err != nil {
			return "", err
		}

		return discoveryResponse.TenantDiscoveryEndpoint, nil
	}

	return authorityInfo.CanonicalAuthorityURI + "v2.0/.well-known/openid-configuration", nil
}

func createOpenIDConfigurationEndpointManager(authorityInfo msalbase.AuthorityInfo) (openIDConfigurationEndpointManager, error) {
	if authorityInfo.AuthorityType == msalbase.MSSTS {
		return &aadOpenIDConfigurationEndpointManager{}, nil
	}

	return nil, fmt.Errorf("unsupported authority type(%v) for createOpenIdConfigurationEndpointManager", authorityInfo.AuthorityType)
}
