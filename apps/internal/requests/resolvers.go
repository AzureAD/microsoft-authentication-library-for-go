// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// TODO(msal): Write some tests. The original code this came from didn't have tests and I'm too
// tired at this point to do it. It, like many other *Manager code I found was broken because
// they didn't have mutex protection.

package requests

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/requests/ops"
)

type cacheEntry struct {
	Endpoints             msalbase.AuthorityEndpoints
	ValidForDomainsInList map[string]bool
}

func createcacheEntry(endpoints msalbase.AuthorityEndpoints) cacheEntry {
	return cacheEntry{endpoints, map[string]bool{}}
}

// AuthorityEndpoint retrieves endpoints from an authority for auth and token acquisition.
type authorityEndpoint struct {
	rest *ops.REST

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// newAuthorityEndpoint is the constructor for AuthorityEndpoint.
func newAuthorityEndpoint(rest *ops.REST) *authorityEndpoint {
	m := &authorityEndpoint{rest: rest}
	return m
}

// ResolveEndpoints gets the authorization and token endpoints and creates an AuthorityEndpoints instance
func (m *authorityEndpoint) ResolveEndpoints(ctx context.Context, authorityInfo msalbase.AuthorityInfo, userPrincipalName string) (msalbase.AuthorityEndpoints, error) {
	if authorityInfo.AuthorityType == msalbase.ADFS && len(userPrincipalName) == 0 {
		return msalbase.AuthorityEndpoints{}, errors.New("UPN required for authority validation for ADFS")
	}

	if endpoints, found := m.cachedEndpoints(authorityInfo, userPrincipalName); found {
		return endpoints, nil
	}

	endpoint, err := m.openIDConfigurationEndpoint(ctx, authorityInfo, userPrincipalName)
	if err != nil {
		return msalbase.AuthorityEndpoints{}, err
	}

	resp, err := m.rest.Authority().GetTenantDiscoveryResponse(ctx, endpoint)
	if err != nil {
		return msalbase.AuthorityEndpoints{}, err
	}
	if err := resp.Validate(); err != nil {
		return msalbase.AuthorityEndpoints{}, fmt.Errorf("ResolveEndpoints(): %w", err)
	}

	tenant := authorityInfo.Tenant

	endpoints := msalbase.CreateAuthorityEndpoints(
		strings.Replace(resp.AuthorizationEndpoint, "{tenant}", tenant, -1),
		strings.Replace(resp.TokenEndpoint, "{tenant}", tenant, -1),
		strings.Replace(resp.Issuer, "{tenant}", tenant, -1),
		authorityInfo.Host)

	m.addCachedEndpoints(authorityInfo, userPrincipalName, endpoints)

	return endpoints, nil
}

// cachedEndpoints returns a the cached endpoints if they exists. If not, we return false.
func (m *authorityEndpoint) cachedEndpoints(authorityInfo msalbase.AuthorityInfo, userPrincipalName string) (msalbase.AuthorityEndpoints, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cacheEntry, ok := m.cache[authorityInfo.CanonicalAuthorityURI]; ok {
		if authorityInfo.AuthorityType == msalbase.ADFS {
			domain, err := getAdfsDomainFromUpn(userPrincipalName)
			if err == nil {
				if _, ok := cacheEntry.ValidForDomainsInList[domain]; ok {
					return cacheEntry.Endpoints, true
				}
			}
		}
		return cacheEntry.Endpoints, true
	}
	return msalbase.AuthorityEndpoints{}, false
}

func (m *authorityEndpoint) addCachedEndpoints(authorityInfo msalbase.AuthorityInfo, userPrincipalName string, endpoints msalbase.AuthorityEndpoints) {
	m.mu.Lock()
	defer m.mu.Unlock()

	updatedCacheEntry := createcacheEntry(endpoints)

	if authorityInfo.AuthorityType == msalbase.ADFS {
		// Since we're here, we've made a call to the backend.  We want to ensure we're caching
		// the latest values from the server.
		if cacheEntry, ok := m.cache[authorityInfo.CanonicalAuthorityURI]; ok {
			for k := range cacheEntry.ValidForDomainsInList {
				updatedCacheEntry.ValidForDomainsInList[k] = true
			}
		}
		domain, err := getAdfsDomainFromUpn(userPrincipalName)
		if err == nil {
			updatedCacheEntry.ValidForDomainsInList[domain] = true
		}
	}

	m.cache[authorityInfo.CanonicalAuthorityURI] = updatedCacheEntry
}

func (m *authorityEndpoint) openIDConfigurationEndpoint(ctx context.Context, authorityInfo msalbase.AuthorityInfo, userPrincipalName string) (string, error) {
	if authorityInfo.ValidateAuthority && !msalbase.TrustedHost(authorityInfo.Host) {
		resp, err := m.rest.Authority().GetAadinstanceDiscoveryResponse(ctx, authorityInfo)
		if err != nil {
			return "", err
		}

		return resp.TenantDiscoveryEndpoint, nil
	}

	return authorityInfo.CanonicalAuthorityURI + "v2.0/.well-known/openid-configuration", nil
}

func getAdfsDomainFromUpn(userPrincipalName string) (string, error) {
	parts := strings.Split(userPrincipalName, "@")
	if len(parts) < 2 {
		return "", errors.New("no @ present in user principal name")
	}
	return parts[1], nil
}
