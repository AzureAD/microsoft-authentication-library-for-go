// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"regexp"
	"strings"
)

// regionPrefixRegex matches a single DNS label (RFC 1035 §2.3.1 / RFC 1123 §2.1).
// Used to shape-check the {region} prefix in a regional host like
// "westus2.login.microsoft.com" before looking up the base. Not an allow-list.
var regionPrefixRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ResolveKnownCloud returns a stable identifier for the Microsoft sovereign cloud
// the host belongs to (case-insensitive), or "" if unknown. Hosts in the same
// cloud return the same identifier so callers can compare with ==. Accepts
// regional sub-hosts of the shape `{region}.{base}`.
func ResolveKnownCloud(host string) string {
	if host == "" {
		return ""
	}
	host = strings.ToLower(host)
	if md, ok := GetKnownMetadata(host); ok {
		return md.PreferredCache
	}
	// Regional sub-host: {region}.{base}
	if i := strings.Index(host, "."); i > 0 {
		prefix := host[:i]
		base := host[i+1:]
		if regionPrefixRegex.MatchString(prefix) {
			if md, ok := GetKnownMetadata(base); ok {
				return md.PreferredCache
			}
		}
	}
	return ""
}

// AreInSameCloud reports whether two hosts belong to the same known Microsoft
// sovereign cloud. Returns false if either host is unknown (default-deny).
func AreInSameCloud(a, b string) bool {
	cloudA := ResolveKnownCloud(a)
	if cloudA == "" {
		return false
	}
	cloudB := ResolveKnownCloud(b)
	if cloudB == "" {
		return false
	}
	return cloudA == cloudB
}

// knownClouds is the authoritative list of Microsoft sovereign clouds. The
// per-host lookup map and TrustedHost are derived from it at init, so editing
// this list is the only place to add a cloud or alias.
var knownClouds = []InstanceDiscoveryMetadata{
	{
		// Public Cloud
		PreferredNetwork: "login.microsoftonline.com",
		PreferredCache:   "login.windows.net",
		Aliases:          []string{"login.microsoftonline.com", "login.windows.net", "login.microsoft.com", "sts.windows.net"},
	},
	{
		// China Cloud (login.chinacloudapi.cn kept for backward compatibility)
		PreferredNetwork: "login.partner.microsoftonline.cn",
		PreferredCache:   "login.partner.microsoftonline.cn",
		Aliases:          []string{"login.partner.microsoftonline.cn", "login.chinacloudapi.cn"},
	},
	{
		// Germany Cloud (legacy)
		PreferredNetwork: "login.microsoftonline.de",
		PreferredCache:   "login.microsoftonline.de",
		Aliases:          []string{"login.microsoftonline.de"},
	},
	{
		// US Government Cloud
		PreferredNetwork: "login.microsoftonline.us",
		PreferredCache:   "login.microsoftonline.us",
		Aliases:          []string{"login.microsoftonline.us", "login.usgovcloudapi.net"},
	},
	{
		// US Regional
		PreferredNetwork: "login-us.microsoftonline.com",
		PreferredCache:   "login-us.microsoftonline.com",
		Aliases:          []string{"login-us.microsoftonline.com"},
	},
	{
		// Bleu (France sovereign cloud)
		PreferredNetwork: "login.sovcloud-identity.fr",
		PreferredCache:   "login.sovcloud-identity.fr",
		Aliases:          []string{"login.sovcloud-identity.fr"},
	},
	{
		// Delos (Germany sovereign cloud)
		PreferredNetwork: "login.sovcloud-identity.de",
		PreferredCache:   "login.sovcloud-identity.de",
		Aliases:          []string{"login.sovcloud-identity.de"},
	},
	{
		// GovSG (Singapore sovereign cloud)
		PreferredNetwork: "login.sovcloud-identity.sg",
		PreferredCache:   "login.sovcloud-identity.sg",
		Aliases:          []string{"login.sovcloud-identity.sg"},
	},
}

// knownHostMetadata is the alias → metadata lookup, derived from knownClouds
// at init so the two views cannot drift.
var knownHostMetadata = func() map[string]InstanceDiscoveryMetadata {
	m := make(map[string]InstanceDiscoveryMetadata)
	for _, cloud := range knownClouds {
		for _, alias := range cloud.Aliases {
			m[alias] = cloud
		}
	}
	return m
}()

// GetKnownMetadata returns the known instance discovery metadata for the given
// host, if any. Each call returns a fresh struct with its own Aliases slice,
// so callers may freely modify the result without affecting future calls.
func GetKnownMetadata(host string) (InstanceDiscoveryMetadata, bool) {
	md, ok := knownHostMetadata[host]
	if !ok {
		return InstanceDiscoveryMetadata{}, false
	}
	md.Aliases = append([]string(nil), md.Aliases...)
	return md, true
}
