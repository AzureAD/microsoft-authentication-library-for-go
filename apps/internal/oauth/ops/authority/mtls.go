// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// Host constants for deriving the mutual-TLS token endpoint. These mirror the rewrite performed by
// MSAL.NET's RegionAndMtlsDiscoveryProvider: public-cloud login hosts normalize to the shared
// mtlsauth.microsoft.com family; any other login.* host is resolved to its preferred-network
// hostname (when known) and then gets a login -> mtlsauth swap.
const (
	loginPrefix        = "login"
	mtlsAuthPrefix     = "mtlsauth"
	publicMtlsAuthHost = "mtlsauth.microsoft.com"
)

// MtlsPoPAuthenticationScheme realizes AuthenticationScheme for mutual-TLS bound
// proof-of-possession tokens (token_type=mtls_pop). The token is bound to the binding certificate
// presented during the mutual-TLS handshake; unlike SHR proof-of-possession there is no req_cnf in
// the request body — the TLS client certificate performs the binding. KeyID is the binding
// certificate's base64url SHA-256 thumbprint (x5t#S256), used only to isolate the token in the cache.
type MtlsPoPAuthenticationScheme struct {
	keyID string
}

// NewMtlsPoPAuthenticationScheme builds an mTLS PoP scheme bound to the leaf of the given binding
// certificate. cert must be the public leaf certificate whose private key is presented on the TLS
// handshake.
func NewMtlsPoPAuthenticationScheme(cert *x509.Certificate) *MtlsPoPAuthenticationScheme {
	thumbprint := sha256.Sum256(cert.Raw)
	return &MtlsPoPAuthenticationScheme{
		keyID: base64.RawURLEncoding.EncodeToString(thumbprint[:]),
	}
}

// TokenRequestParams adds token_type=mtls_pop to the token request body. It deliberately does not
// add req_cnf: the mutual-TLS client certificate performs the binding.
func (m *MtlsPoPAuthenticationScheme) TokenRequestParams() map[string]string {
	return map[string]string{
		"token_type": AccessTokenTypeMtlsPoP,
	}
}

// KeyID returns the binding certificate's x5t#S256 thumbprint, used to isolate mtls_pop tokens in
// the cache by certificate.
func (m *MtlsPoPAuthenticationScheme) KeyID() string {
	return m.keyID
}

// FormatAccessToken returns the access token unchanged; the caller presents the binding certificate
// on the connection to the resource, so no Authorization-header transformation is applied here.
func (m *MtlsPoPAuthenticationScheme) FormatAccessToken(accessToken string) (string, error) {
	return accessToken, nil
}

// AccessTokenType returns mtls_pop, matching the token_type ESTS returns for these tokens.
func (m *MtlsPoPAuthenticationScheme) AccessTokenType() string {
	return AccessTokenTypeMtlsPoP
}

// isPublicMtlsEnvironment reports whether host is a well-known worldwide public-cloud login host.
// These all normalize to the shared mtlsauth.microsoft.com endpoint family. host must already have
// any port stripped and be lowercased.
//
// sts.windows.net is deliberately absent even though it is a public-cloud alias: it has no login.
// prefix, so MtlsTokenEndpoint rejects it before reaching this function. Listing it here would
// suggest mTLS PoP is supported for it. MSAL .NET rejects it the same way, through the login.-prefix
// check in RegionAndMtlsDiscoveryProvider.
func isPublicMtlsEnvironment(host string) bool {
	switch host {
	case defaultHost, loginMicrosoft, loginWindows:
		return true
	}
	return false
}

// MtlsTokenEndpoint derives the mutual-TLS token endpoint for an mTLS PoP request from the resolved
// token endpoint and authority info. It rewrites the host from login.* to mtlsauth.* (preserving any
// region prefix) and fails fast for authorities that don't support mTLS PoP:
//   - non-login.* hosts,
//   - non-tenanted authorities (/common, /organizations, /consumers).
//
// The worldwide public hosts collapse to the shared mtlsauth.microsoft.com family. Every sovereign
// cloud is supported: a legacy alias is first normalized to its preferred-network host
// (login.usgovcloudapi.net -> login.microsoftonline.us, login.chinacloudapi.cn ->
// login.partner.microsoftonline.cn) and only then swapped to mtlsauth.*, so aliases resolve to the
// same endpoint as their modern hostname rather than a host that doesn't exist. This mirrors
// MSAL.NET's RegionAndMtlsDiscoveryProvider.
//
// When a concrete region is configured the endpoint is regionalized ({region}.mtlsauth...);
// otherwise the global endpoint is used (region is optional — global mtlsauth.microsoft.com is
// production-ready). Callers who asked for auto-detection get a concrete region here because
// Info.ResolveRegion replaces the sentinel earlier in the request, during endpoint resolution.
//
// ADFS and dSTS are out of scope for mTLS PoP. Neither serves a login.* host, so both are rejected
// by the host check with the same message any other unsupported authority gets. MSAL .NET behaves
// identically: its dedicated dSTS rejection message is dead code, and dSTS is in practice refused by
// the same login.-prefix guard.
func (p AuthParams) MtlsTokenEndpoint() (string, error) {
	// AuthorityInfo.Host can carry an explicit port (it comes from url.URL.Host, and private cloud
	// deployments rely on that), so split it off before matching against known hosts. Otherwise
	// "login.microsoftonline.com:443" misses every lookup and falls through to a literal swap that
	// produces "mtlsauth.microsoftonline.com:443" instead of the normalized public host. MSAL .NET
	// can't hit this because it reads Uri.Host, which excludes the port by construction.
	host, port := splitHostPort(strings.ToLower(p.AuthorityInfo.Host))
	tenant := p.AuthorityInfo.Tenant

	// Go rejects a wider set of non-tenanted authorities than MSAL .NET's
	// AadAuthority.IsCommonOrOrganizationsTenant does. That superset is intentional: none of these
	// can produce a tenant-bound mTLS PoP token, so catching them all here is better than letting
	// ESTS reject the request on the network.
	if tenant == "" ||
		strings.EqualFold(tenant, "common") ||
		strings.EqualFold(tenant, "organizations") ||
		strings.EqualFold(tenant, "consumers") {
		return "", fmt.Errorf("mTLS proof-of-possession requires a tenanted authority; %q is not a specific tenant", tenant)
	}
	if !strings.HasPrefix(host, loginPrefix+".") {
		return "", fmt.Errorf("mTLS proof-of-possession is not supported for authority host %q; a login.* host is required", p.AuthorityInfo.Host)
	}

	var mtlsHost string
	if isPublicMtlsEnvironment(host) {
		mtlsHost = publicMtlsAuthHost
	} else {
		// Normalize a known alias to its preferred-network host first, so legacy sovereign
		// hostnames land on the endpoint their modern equivalent uses (for example
		// login.usgovcloudapi.net -> login.microsoftonline.us -> mtlsauth.microsoftonline.us)
		// instead of a literal swap to a host that isn't served.
		if md, ok := GetKnownMetadata(host); ok && strings.HasPrefix(md.PreferredNetwork, loginPrefix+".") {
			host = md.PreferredNetwork
		}
		// login.<rest> -> mtlsauth.<rest>
		mtlsHost = mtlsAuthPrefix + host[len(loginPrefix):]
	}
	if region := p.AuthorityInfo.Region; region != "" && region != autoDetectRegion {
		mtlsHost = region + "." + mtlsHost
	}
	if port != "" {
		mtlsHost += ":" + port
	}

	// Preserve the resolved token endpoint's path/query, swapping only the host.
	if p.Endpoints.TokenEndpoint != "" {
		if u, err := url.Parse(p.Endpoints.TokenEndpoint); err == nil && u.Host != "" {
			u.Host = mtlsHost
			return u.String(), nil
		}
	}
	return fmt.Sprintf("https://%s/%s/oauth2/v2.0/token", mtlsHost, tenant), nil
}

// splitHostPort separates an "host:port" authority host into its parts. Unlike net.SplitHostPort it
// tolerates a bare hostname, returning an empty port, and leaves an IPv6 literal's brackets in place
// so the value can be reassembled verbatim.
func splitHostPort(hostport string) (host, port string) {
	i := strings.LastIndex(hostport, ":")
	if i < 0 || i < strings.LastIndex(hostport, "]") {
		return hostport, ""
	}
	return hostport[:i], hostport[i+1:]
}
