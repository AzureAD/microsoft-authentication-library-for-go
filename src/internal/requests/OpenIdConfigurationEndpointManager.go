package requests

import (
	"errors"

	"github.com/markzuber/msalgo/internal/msalbase"
)

type IOpenIdConfigurationEndpointManager interface {
	getOpenIdConfigurationEndpoint(authorityInfo *msalbase.AuthorityInfo, userPrincipalName string) (string, error)
}

type aadOpenIdConfigurationEndpointManager struct {
	aadInstanceDiscovery IAadInstanceDiscovery
}

func createAadOpenIdConfigurationEndpointManager(aadInstanceDiscovery IAadInstanceDiscovery) IOpenIdConfigurationEndpointManager {
	m := &aadOpenIdConfigurationEndpointManager{aadInstanceDiscovery}
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

func isInTrustedHostList(host string) bool {
	if _, ok := aadTrustedHostList[host]; ok {
		return true
	}
	return false
}

func (m *aadOpenIdConfigurationEndpointManager) getOpenIdConfigurationEndpoint(authorityInfo *msalbase.AuthorityInfo, userPrincipalName string) (string, error) {
	if authorityInfo.GetValidateAuthority() && !isInTrustedHostList(authorityInfo.GetHost()) {
		discoveryResponse, err := m.aadInstanceDiscovery.GetMetadataEntry(authorityInfo)
		if err != nil {
			return "", err
		}

		return discoveryResponse.TenantDiscoveryEndpoint, nil
	}

	return authorityInfo.GetCanonicalAuthorityURI() + "v2.0/.well-known/openid-configuration", nil
}

func createOpenIdConfigurationEndpointManager(authorityInfo *msalbase.AuthorityInfo) (IOpenIdConfigurationEndpointManager, error) {
	if authorityInfo.GetAuthorityType() == msalbase.AuthorityTypeAad {
		return &aadOpenIdConfigurationEndpointManager{}, nil
	}

	return nil, errors.New("Unsupported authority type for createOpenIdConfigurationEndpointManager: " + string(authorityInfo.GetAuthorityType()))
}
