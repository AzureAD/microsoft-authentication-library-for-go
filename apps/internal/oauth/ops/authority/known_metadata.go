// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

// knownMetadata maps cloud authority hosts to their instance discovery metadata.
// This allows correct alias resolution even when the instance discovery endpoint
// is unreachable.
var knownMetadata map[string]InstanceDiscoveryMetadata

func init() {
	publicCloud := InstanceDiscoveryMetadata{
		PreferredNetwork: "login.microsoftonline.com",
		PreferredCache:   "login.windows.net",
		Aliases:          []string{"login.microsoftonline.com", "login.windows.net", "login.microsoft.com", "sts.windows.net"},
	}
	chinaCloud := InstanceDiscoveryMetadata{
		PreferredNetwork: "login.partner.microsoftonline.cn",
		PreferredCache:   "login.partner.microsoftonline.cn",
		Aliases:          []string{"login.partner.microsoftonline.cn", "login.chinacloudapi.cn"},
	}
	germanyCloud := InstanceDiscoveryMetadata{
		PreferredNetwork: "login.microsoftonline.de",
		PreferredCache:   "login.microsoftonline.de",
		Aliases:          []string{"login.microsoftonline.de"},
	}
	usGovCloud := InstanceDiscoveryMetadata{
		PreferredNetwork: "login.microsoftonline.us",
		PreferredCache:   "login.microsoftonline.us",
		Aliases:          []string{"login.microsoftonline.us", "login.usgovcloudapi.net"},
	}
	usRegionalCloud := InstanceDiscoveryMetadata{
		PreferredNetwork: "login-us.microsoftonline.com",
		PreferredCache:   "login-us.microsoftonline.com",
		Aliases:          []string{"login-us.microsoftonline.com"},
	}
	bleuCloud := InstanceDiscoveryMetadata{
		PreferredNetwork: "login.sovcloud-identity.fr",
		PreferredCache:   "login.sovcloud-identity.fr",
		Aliases:          []string{"login.sovcloud-identity.fr"},
	}
	delosCloud := InstanceDiscoveryMetadata{
		PreferredNetwork: "login.sovcloud-identity.de",
		PreferredCache:   "login.sovcloud-identity.de",
		Aliases:          []string{"login.sovcloud-identity.de"},
	}
	govSGCloud := InstanceDiscoveryMetadata{
		PreferredNetwork: "login.sovcloud-identity.sg",
		PreferredCache:   "login.sovcloud-identity.sg",
		Aliases:          []string{"login.sovcloud-identity.sg"},
	}

	knownMetadata = map[string]InstanceDiscoveryMetadata{
		// Public Cloud
		"login.microsoftonline.com": publicCloud,
		"login.windows.net":         publicCloud,
		"login.microsoft.com":       publicCloud,
		"sts.windows.net":           publicCloud,
		// China Cloud
		"login.partner.microsoftonline.cn": chinaCloud,
		"login.chinacloudapi.cn":           chinaCloud,
		// Germany Cloud (legacy)
		"login.microsoftonline.de": germanyCloud,
		// US Government Cloud
		"login.microsoftonline.us": usGovCloud,
		"login.usgovcloudapi.net":  usGovCloud,
		// US Regional
		"login-us.microsoftonline.com": usRegionalCloud,
		// Bleu (France)
		"login.sovcloud-identity.fr": bleuCloud,
		// Delos (Germany)
		"login.sovcloud-identity.de": delosCloud,
		// GovSG (Singapore)
		"login.sovcloud-identity.sg": govSGCloud,
	}
}

// GetKnownMetadata returns the known metadata entry for the given host, if any.
func GetKnownMetadata(host string) (InstanceDiscoveryMetadata, bool) {
	md, ok := knownMetadata[host]
	return md, ok
}
