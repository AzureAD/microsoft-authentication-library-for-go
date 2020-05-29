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

// package global static
var endpointCacheEntries = map[string]*authorityEndpointCacheEntry{}

type IAuthorityEndpointResolutionManager interface {
	ResolveEndpoints(authorityInfo *msalbase.AuthorityInfo, userPrincipalName string) (*msalbase.AuthorityEndpoints, error)
}

type AuthorityEndpointResolutionManager struct {
	webRequestManager IWebRequestManager
}

func CreateAuthorityEndpointResolutionManager(webRequestManager IWebRequestManager) IAuthorityEndpointResolutionManager {
	m := &AuthorityEndpointResolutionManager{webRequestManager}
	return m
}

func getAdfsDomainFromUpn(userPrincipalName string) string {
	// todo: func should return error so we can handle not having a @ in the string...
	return strings.Split(userPrincipalName, "@")[1]
}

func (m *AuthorityEndpointResolutionManager) tryGetCachedEndpoints(authorityInfo *msalbase.AuthorityInfo, userPrincipalName string) *msalbase.AuthorityEndpoints {

	if cacheEntry, ok := endpointCacheEntries[authorityInfo.GetCanonicalAuthorityURI()]; ok {
		log.Infof("%#v", cacheEntry.Endpoints)
		if authorityInfo.GetAuthorityType() == msalbase.AuthorityTypeAdfs {
			if _, ok := cacheEntry.ValidForDomainsInList[getAdfsDomainFromUpn(userPrincipalName)]; ok {
				return cacheEntry.Endpoints
			}
		} else {
			return cacheEntry.Endpoints
		}
	}
	return nil
}

func (m *AuthorityEndpointResolutionManager) addCachedEndpoints(authorityInfo *msalbase.AuthorityInfo, userPrincipalName string, endpoints *msalbase.AuthorityEndpoints) {
	updatedCacheEntry := createAuthorityEndpointCacheEntry(endpoints)

	if authorityInfo.GetAuthorityType() == msalbase.AuthorityTypeAdfs {
		// Since we're here, we've made a call to the backend.  We want to ensure we're caching
		// the latest values from the server.
		if cacheEntry, ok := endpointCacheEntries[authorityInfo.GetCanonicalAuthorityURI()]; ok {
			for k, _ := range cacheEntry.ValidForDomainsInList {
				updatedCacheEntry.ValidForDomainsInList[k] = true
			}
		}

		updatedCacheEntry.ValidForDomainsInList[getAdfsDomainFromUpn(userPrincipalName)] = true
	}

	endpointCacheEntries[authorityInfo.GetCanonicalAuthorityURI()] = updatedCacheEntry
}

func (m *AuthorityEndpointResolutionManager) ResolveEndpoints(authorityInfo *msalbase.AuthorityInfo, userPrincipalName string) (*msalbase.AuthorityEndpoints, error) {

	if authorityInfo.GetAuthorityType() == msalbase.AuthorityTypeAdfs && len(userPrincipalName) == 0 {
		return nil, errors.New("UPN Required for Authority Validation for ADFS")
	}

	endpoints := m.tryGetCachedEndpoints(authorityInfo, userPrincipalName)
	if endpoints != nil {
		log.Info("Resolving authority endpoints. Using cached value")
		return endpoints, nil
	}

	log.Info("Resolving authority endpoints. No cached value.  Performing lookup.")
	endpointManager, err := createOpenIdConfigurationEndpointManager(authorityInfo)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	openIDConfigurationEndpoint, err := endpointManager.getOpenIdConfigurationEndpoint(authorityInfo, userPrincipalName)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	// Discover endpoints via openid-configuration
	tenantDiscoveryResponse, err := m.webRequestManager.GetTenantDiscoveryResponse(openIDConfigurationEndpoint)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	if !tenantDiscoveryResponse.HasAuthorizationEndpoint() {
		return nil, errors.New("Authorize endpoint was not found in the openid configuration")
	}
	if !tenantDiscoveryResponse.HasTokenEndpoint() {
		return nil, errors.New("Token endpoint was not found in the openid configuration")
	}
	if !tenantDiscoveryResponse.HasIssuer() {
		return nil, errors.New("Issuer was not found in the openid configuration")
	}

	tenant := authorityInfo.Tenant()

	endpoints = msalbase.CreateAuthorityEndpoints(
		strings.Replace(tenantDiscoveryResponse.AuthorizationEndpoint, "{tenant}", tenant, -1),
		strings.Replace(tenantDiscoveryResponse.TokenEndpoint, "{tenant}", tenant, -1),
		strings.Replace(tenantDiscoveryResponse.Issuer, "{tenant}", tenant, -1),
		authorityInfo.GetHost())

	m.addCachedEndpoints(authorityInfo, userPrincipalName, endpoints)

	log.Infof("Endpoints: %#v", endpoints)

	return endpoints, nil
}
