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
// mtlsauth.microsoft.com family; any other trusted login.* host is resolved to its preferred-network
// hostname (when known) and then gets a login -> mtlsauth swap. ValidateMtlsPoP decides which hosts
// may be rewritten at all.
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

// ValidateMtlsPoP reports whether this authority can serve mTLS proof-of-possession tokens. mTLS PoP
// requires an AAD authority (AuthorityType == AAD), tenanted (not /common, /organizations or
// /consumers), on a login.* host that is either a known Microsoft cloud or a private cloud the
// caller has explicitly chosen to trust.
//
// It is called both early in the acquisition, before any credential resolution result is used or any
// network work happens, and again from MtlsTokenEndpoint so the network path is never left
// unguarded. MSAL .NET validates at the same point - ValidateAadAuthorityForPop runs from
// MtlsPopParametersInitializer during parameter initialization, before cache or discovery work.
func (i Info) ValidateMtlsPoP() error {
	// The authority type is checked first because it depends on nothing else here and it is the
	// categorical answer: mTLS PoP is an AAD protocol, so a non-AAD authority can never serve it no
	// matter what its tenant or host look like. Checking the host first would be both wrong and
	// misleading. Wrong, because AuthorityType is decided by the authority's first path segment and
	// never by its host (see NewInfoFromAuthorityURI), so a non-AAD authority can sit on a login.*
	// host and satisfy every other check here - https://login.microsoftonline.com/adfs and
	// https://login.microsoftonline.com/dstsv2/<tenant> both do. Misleading, because it would tell
	// an ADFS or dSTS caller to bring a login.* host, which would not help.
	//
	// AAD's value is "MSSTS", so the zero value of Info is not an AAD authority and this guard fails
	// closed for any Info that was assembled by hand rather than parsed from an authority URL.
	if i.AuthorityType != AAD {
		return fmt.Errorf("mTLS proof-of-possession is not supported for authority type %q; an AAD (%s) authority is required", i.AuthorityType, AAD)
	}
	// Go rejects a wider set of non-tenanted authorities than MSAL .NET's
	// AadAuthority.IsCommonOrOrganizationsTenant does. That superset is intentional: none of these
	// can produce a tenant-bound mTLS PoP token, so catching them all here is better than letting
	// ESTS reject the request on the network. The comparison is case-insensitive so the guard holds
	// on its own rather than depending on the authority URL having been lowercased at parse time.
	if i.Tenant == "" ||
		strings.EqualFold(i.Tenant, "common") ||
		strings.EqualFold(i.Tenant, "organizations") ||
		strings.EqualFold(i.Tenant, "consumers") {
		return fmt.Errorf("mTLS proof-of-possession requires a tenanted authority; %q is not a specific tenant", i.Tenant)
	}
	// AuthorityInfo.Host can carry an explicit port (it comes from url.URL.Host, and private cloud
	// deployments rely on that), so split it off before matching against known hosts.
	host, _ := splitHostPort(strings.ToLower(i.Host))
	if !strings.HasPrefix(host, loginPrefix+".") {
		return fmt.Errorf("mTLS proof-of-possession is not supported for authority host %q; a login.* host is required", i.Host)
	}
	// The host trust check is last because it is the narrowest: it only makes sense once the host is
	// known to be a login.* host that MtlsTokenEndpoint would rewrite.
	//
	// MtlsTokenEndpoint turns login.<rest> into mtlsauth.<rest> and then presents the binding
	// certificate - and, since the FIC work, a live client assertion - to whatever that host
	// resolves to. Without this guard any attacker-influenced authority derives a matching mtlsauth
	// host (login.evil.test -> mtlsauth.evil.test) and receives those credentials, so the rewrite is
	// allowed only for a host backed by trusted cloud metadata.
	//
	// TrustedHost is the same predicate the bearer path uses to decide whether an authority needs
	// instance discovery (see openIDConfigurationEndpoint), so mTLS PoP trusts exactly the set the
	// rest of the library already trusts, and TestTrustedHostsHaveKnownMetadata pins that everything
	// in it also has GetKnownMetadata to normalize against. Every sovereign cloud is in that set, so
	// this does not repeat MSAL .NET's #6153, where extra host rejection broke mTLS PoP in Azure
	// China.
	//
	// Private clouds are not in any static list, so they opt in instead, with the option that
	// already exists for exactly this purpose: WithInstanceDiscovery(false), documented as
	// "disable authority validation (to support private cloud scenarios)". That is a deliberate
	// decision by the application to trust its own authority host, which is the explicit trust
	// signal this guard needs. InstanceDiscoveryDisabled is used rather than !ValidateAuthority
	// because the two are set together from that one option but only this one fails closed on a
	// zero-value Info.
	if !TrustedHost(host) && !i.InstanceDiscoveryDisabled {
		return fmt.Errorf("mTLS proof-of-possession is not supported for authority host %q; it is not a known Microsoft cloud host, so a private cloud must opt in with WithInstanceDiscovery(false) before its %s.* endpoint is derived", i.Host, mtlsAuthPrefix)
	}
	return nil
}

// MtlsTokenEndpoint derives the mutual-TLS token endpoint for an mTLS PoP request from the resolved
// token endpoint and authority info. It rewrites the host from login.* to mtlsauth.* (preserving any
// region prefix) and fails fast for authorities that don't support mTLS PoP; see ValidateMtlsPoP.
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
// ADFS and dSTS are out of scope for mTLS PoP, and ValidateMtlsPoP refuses them by authority type.
// The login.-prefix host check does not catch them: AuthorityType comes from the authority's first
// path segment and never from its host, so https://login.microsoftonline.com/adfs and
// https://login.microsoftonline.com/dstsv2/<tenant> are both served from a login.* host and, before
// the type check existed, derived an mtlsauth.* endpoint. MSAL .NET's dedicated dSTS rejection
// message is dead code and dSTS is in practice refused there by its login.-prefix guard, because its
// authorities are not login.*-hosted; Go does not rely on that.
//
// A login.* host that is not a known Microsoft cloud is rewritten only when the caller has made an
// explicit private-cloud trust decision, because this host receives the binding certificate and the
// client assertion. See ValidateMtlsPoP.
func (p AuthParams) MtlsTokenEndpoint() (string, error) {
	if err := p.AuthorityInfo.ValidateMtlsPoP(); err != nil {
		return "", err
	}
	// The port is preserved so a private cloud deployment on a non-default port still reaches its
	// own endpoint. MSAL .NET can't hit this because it reads Uri.Host, which excludes the port by
	// construction.
	host, port := splitHostPort(strings.ToLower(p.AuthorityInfo.Host))
	tenant := p.AuthorityInfo.Tenant

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
