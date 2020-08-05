// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"errors"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type authorityEndpointCacheEntry struct {
	Endpoints             *msalbase.AuthorityEndpoints
	ValidForDomainsInList map[string]bool
}

func createAuthorityEndpointCacheEntry(endpoints *msalbase.AuthorityEndpoints) *authorityEndpointCacheEntry {
	return &authorityEndpointCacheEntry{endpoints, make(map[string]bool)}
}

var endpointCacheEntries = map[string]*authorityEndpointCacheEntry{}

//AuthorityEndpointResolutionManager handles getting the correct endpoints from the authority for auth and token acquisition
type AuthorityEndpointResolutionManager struct {
	webRequestManager WebRequestManager
}

//CreateAuthorityEndpointResolutionManager creates a AuthorityEndpointResolutionManager instance
func CreateAuthorityEndpointResolutionManager(webRequestManager WebRequestManager) *AuthorityEndpointResolutionManager {
	m := &AuthorityEndpointResolutionManager{webRequestManager}
	return m
}

func getAdfsDomainFromUpn(userPrincipalName string) (string, error) {
	parts := strings.Split(userPrincipalName, "@")
	if len(parts) < 2 {
		return "", errors.New("no @ present in user principal name")
	}
	return parts[1], nil
}

func (m *AuthorityEndpointResolutionManager) tryGetCachedEndpoints(authorityInfo *msalbase.AuthorityInfo, userPrincipalName string) *msalbase.AuthorityEndpoints {

	if cacheEntry, ok := endpointCacheEntries[authorityInfo.CanonicalAuthorityURI]; ok {
		if authorityInfo.AuthorityType == msalbase.ADFS {
			domain, err := getAdfsDomainFromUpn(userPrincipalName)
			if err == nil {
				if _, ok := cacheEntry.ValidForDomainsInList[domain]; ok {
					return cacheEntry.Endpoints
				}
			}
		} else {
			return cacheEntry.Endpoints
		}
	}
	return nil
}

func (m *AuthorityEndpointResolutionManager) addCachedEndpoints(authorityInfo *msalbase.AuthorityInfo, userPrincipalName string, endpoints *msalbase.AuthorityEndpoints) {
	updatedCacheEntry := createAuthorityEndpointCacheEntry(endpoints)

	if authorityInfo.AuthorityType == msalbase.ADFS {
		// Since we're here, we've made a call to the backend.  We want to ensure we're caching
		// the latest values from the server.
		if cacheEntry, ok := endpointCacheEntries[authorityInfo.CanonicalAuthorityURI]; ok {
			for k := range cacheEntry.ValidForDomainsInList {
				updatedCacheEntry.ValidForDomainsInList[k] = true
			}
		}
		domain, err := getAdfsDomainFromUpn(userPrincipalName)
		if err == nil {
			updatedCacheEntry.ValidForDomainsInList[domain] = true
		}
	}

	endpointCacheEntries[authorityInfo.CanonicalAuthorityURI] = updatedCacheEntry
}

//ResolveEndpoints gets the authorization and token endpoints and creates an AuthorityEndpoints instance
func (m *AuthorityEndpointResolutionManager) ResolveEndpoints(authorityInfo *msalbase.AuthorityInfo, userPrincipalName string) (*msalbase.AuthorityEndpoints, error) {

	if authorityInfo.AuthorityType == msalbase.ADFS && len(userPrincipalName) == 0 {
		return nil, errors.New("UPN required for authority validation for ADFS")
	}

	endpoints := m.tryGetCachedEndpoints(authorityInfo, userPrincipalName)
	if endpoints != nil {
		log.Info("Resolving authority endpoints. Using cached value")
		return endpoints, nil
	}

	log.Info("Resolving authority endpoints. No cached value.  Performing lookup.")
	endpointManager, err := createOpenIDConfigurationEndpointManager(authorityInfo)
	if err != nil {
		return nil, err
	}

	openIDConfigurationEndpoint, err := endpointManager.getOpenIDConfigurationEndpoint(authorityInfo, userPrincipalName)
	if err != nil {
		return nil, err
	}

	// Discover endpoints via openid-configuration
	tenantDiscoveryResponse, err := m.webRequestManager.GetTenantDiscoveryResponse(openIDConfigurationEndpoint)
	if err != nil {
		return nil, err
	}

	if !tenantDiscoveryResponse.HasAuthorizationEndpoint() {
		return nil, errors.New("authorize endpoint was not found in the openid configuration")
	}
	if !tenantDiscoveryResponse.HasTokenEndpoint() {
		return nil, errors.New("token endpoint was not found in the openid configuration")
	}
	if !tenantDiscoveryResponse.HasIssuer() {
		return nil, errors.New("issuer was not found in the openid configuration")
	}

	tenant := authorityInfo.Tenant

	endpoints = msalbase.CreateAuthorityEndpoints(
		strings.Replace(tenantDiscoveryResponse.AuthorizationEndpoint, "{tenant}", tenant, -1),
		strings.Replace(tenantDiscoveryResponse.TokenEndpoint, "{tenant}", tenant, -1),
		strings.Replace(tenantDiscoveryResponse.Issuer, "{tenant}", tenant, -1),
		authorityInfo.Host)

	m.addCachedEndpoints(authorityInfo, userPrincipalName, endpoints)

	return endpoints, nil
}
