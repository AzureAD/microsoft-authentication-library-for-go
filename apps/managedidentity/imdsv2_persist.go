// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"crypto/x509"
	"os"
	"strings"
)

// disablePersistentCertCacheEnvVar turns the persistent certificate cache off.
// It is the same switch MSAL .NET reads in PersistentCertificateCacheFactory,
// so an operator who has to disable persistence does it once for the machine
// rather than once per library.
const disablePersistentCertCacheEnvVar = "MSAL_MI_DISABLE_PERSISTENT_CERT_CACHE"

// persistedCertificate is a binding certificate recovered from the operating
// system store, without the private key.
//
// The key is deliberately absent. It lives in a CNG container under a fixed
// name, so it is reopened through the ordinary key provider and paired with
// this certificate by the caller. That also means the pairing goes through the
// same public key comparison a freshly issued certificate does, rather than
// trusting whatever the store happened to hand back.
type persistedCertificate struct {
	DER      []byte
	Leaf     *x509.Certificate
	ClientID string
	TenantID string
	Endpoint string
}

// persistentCertCache stores issued binding certificates somewhere that
// outlives the process.
//
// Every method is best effort and none of them returns an error: persistence is
// an optimisation that keeps a restart from re-issuing a credential, and a
// store that cannot be reached must never stop a token from being acquired.
// MSAL .NET makes the same choice in IPersistentCertificateCache.
type persistentCertCache interface {
	// read returns the newest certificate stored for alias that still has at
	// least bindingCertRefreshWindow of life left and that names the container
	// the binding key lives in. Naming the container is all a store can check
	// cheaply; whether the key is still there, and so whether the entry is
	// orphaned, is settled by bindingCertCache.restore, which opens the key and
	// calls deleteAll when it has gone.
	read(alias string) (*persistedCertificate, bool)
	// write stores cert for alias and prunes expired entries.
	write(alias string, cert *bindingCertificate)
	// deleteAll removes every entry for alias, expired or not. It is what runs
	// when the service rejects a certificate, so the next acquisition cannot
	// find the rejected certificate again.
	deleteAll(alias string)
}

// noopPersistentCertCache is used wherever persistence is unavailable or has
// been switched off. It is not an error state: the in-memory cache still works,
// a restart simply costs one credential request.
type noopPersistentCertCache struct{}

func (noopPersistentCertCache) read(string) (*persistedCertificate, bool) { return nil, false }
func (noopPersistentCertCache) write(string, *bindingCertificate)         {}
func (noopPersistentCertCache) deleteAll(string)                          {}

// newPersistentCertCache returns the persistent cache for this host.
func newPersistentCertCache() persistentCertCache {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(disablePersistentCertCacheEnvVar))) {
	case "1", "true":
		return noopPersistentCertCache{}
	}
	return newPlatformPersistentCertCache()
}

// The friendly name is the only place a certificate in the store can carry the
// identity it was issued for, so it is what scopes a lookup. The grammar is
// MSAL .NET's, from MsiCertificateFriendlyNameEncoder:
//
//	MSAL|alias=<alias>|ep=<endpoint>/<tenant>
//
// Values are not escaped, so a value containing the separator or a line break
// would produce a name that does not decode to what was encoded. Rather than
// invent an escaping scheme the two libraries would have to agree on, such a
// value is refused and the certificate is simply not persisted.
const (
	friendlyNamePrefix   = "MSAL|"
	friendlyNameTagAlias = "alias"
	friendlyNameTagEp    = "ep"
)

// encodeFriendlyName renders alias and endpointBase into the stored form.
func encodeFriendlyName(alias, endpointBase string) (string, bool) {
	alias = strings.TrimSpace(alias)
	endpointBase = strings.TrimSpace(endpointBase)
	if alias == "" || endpointBase == "" {
		return "", false
	}
	if containsFriendlyNameSeparator(alias) || containsFriendlyNameSeparator(endpointBase) {
		return "", false
	}
	return friendlyNamePrefix + friendlyNameTagAlias + "=" + alias + "|" + friendlyNameTagEp + "=" + endpointBase, true
}

// decodeFriendlyName recovers alias and endpointBase from the stored form.
//
// Unknown key=value pairs are ignored rather than rejected, so a certificate
// written by a newer library that records more than these two fields is still
// readable here. That is the forward compatibility rule MSAL .NET documents for
// the same grammar.
func decodeFriendlyName(name string) (alias, endpointBase string, ok bool) {
	if !strings.HasPrefix(name, friendlyNamePrefix) {
		return "", "", false
	}
	for _, part := range strings.Split(strings.TrimPrefix(name, friendlyNamePrefix), "|") {
		if part == "" {
			continue
		}
		sep := strings.Index(part, "=")
		if sep < 0 {
			continue
		}
		key := strings.TrimSpace(part[:sep])
		value := strings.TrimSpace(part[sep+1:])
		switch key {
		case friendlyNameTagAlias:
			alias = value
		case friendlyNameTagEp:
			endpointBase = value
		}
	}
	if alias == "" || endpointBase == "" {
		return "", "", false
	}
	return alias, endpointBase, true
}

func containsFriendlyNameSeparator(value string) bool {
	return strings.ContainsAny(value, "|\r\n\x00")
}

// endpointBase joins the token endpoint and tenant the way MSAL .NET does in
// ImdsV2ManagedIdentitySource, so a certificate written by either library
// decodes to the same two values in the other.
func endpointBase(endpoint, tenantID string) string {
	return strings.TrimRight(endpoint, "/") + "/" + strings.Trim(tenantID, "/")
}

// splitEndpointBase reverses endpointBase.
//
// The tenant is the last segment, and the endpoint keeps everything before it,
// because the endpoint is an origin that may itself contain slashes after the
// scheme.
func splitEndpointBase(base string) (endpoint, tenantID string, ok bool) {
	slash := strings.LastIndex(base, "/")
	if slash <= 0 || slash == len(base)-1 {
		return "", "", false
	}
	endpoint = base[:slash]
	tenantID = base[slash+1:]
	if endpoint == "" || tenantID == "" {
		return "", "", false
	}
	return endpoint, tenantID, true
}
