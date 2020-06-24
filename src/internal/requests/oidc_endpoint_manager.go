// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"errors"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type IOpenIDConfigurationEndpointManager interface {
	getOpenIDConfigurationEndpoint(authorityInfo *msalbase.AuthorityInfo, userPrincipalName string) (string, error)
}

type aadOpenIDConfigurationEndpointManager struct {
	aadInstanceDiscovery IAadInstanceDiscovery
}

func createAadOpenIDConfigurationEndpointManager(aadInstanceDiscovery IAadInstanceDiscovery) IOpenIDConfigurationEndpointManager {
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

func IsInTrustedHostList(host string) bool {
	if _, ok := aadTrustedHostList[host]; ok {
		return true
	}
	return false
}

func (m *aadOpenIDConfigurationEndpointManager) getOpenIDConfigurationEndpoint(authorityInfo *msalbase.AuthorityInfo, userPrincipalName string) (string, error) {
	if authorityInfo.GetValidateAuthority() && !IsInTrustedHostList(authorityInfo.GetHost()) {
		discoveryResponse, err := m.aadInstanceDiscovery.GetMetadataEntry(authorityInfo)
		if err != nil {
			return "", err
		}

		return discoveryResponse.TenantDiscoveryEndpoint, nil
	}

	return authorityInfo.GetCanonicalAuthorityURI() + "v2.0/.well-known/openid-configuration", nil
}

func createOpenIDConfigurationEndpointManager(authorityInfo *msalbase.AuthorityInfo) (IOpenIDConfigurationEndpointManager, error) {
	if authorityInfo.GetAuthorityType() == msalbase.AuthorityTypeAad {
		return &aadOpenIDConfigurationEndpointManager{}, nil
	}

	return nil, errors.New("Unsupported authority type for createOpenIdConfigurationEndpointManager: " + string(authorityInfo.GetAuthorityType()))
}
