// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// IMDSv2 issues a short-lived, VM-bound X.509 certificate that is then used as
// a TLS client certificate against a regional Entra endpoint. Acquiring a token
// takes three legs:
//
//  1. GET  /metadata/identity/getplatformmetadata  - learn the client ID,
//     tenant ID and compute identifier this VM should request a credential for.
//  2. POST /metadata/identity/issuecredential      - exchange a CSR, signed by a
//     KeyGuard key, for a certificate signed by IMDS.
//  3. POST {mtls_authentication_endpoint}/{tenant}/oauth2/v2.0/token - present
//     that certificate over mTLS and receive an mTLS proof-of-possession or
//     bearer token.
//
// Legs 1 and 2 speak plain HTTP to the link-local address; only leg 3 uses TLS.
const (
	imdsV2DefaultBaseEndpoint    = "http://169.254.169.254"
	imdsV2CsrMetadataPath        = "/metadata/identity/getplatformmetadata"
	imdsV2IssueCredentialPath    = "/metadata/identity/issuecredential"
	imdsV2OAuthPath              = "/oauth2/v2.0/token"
	imdsV2APIVersionQueryParam   = "cred-api-version"
	imdsV2APIVersion             = "2.0"
	imdsV2MetadataHeader         = "Metadata"
	imdsV2CorrelationIDHeader    = "X-Ms-Correlation-Id"
	imdsV2ClientRequestIDHeader  = "x-ms-client-request-id"
	imdsV2ServerHeader           = "Server"
	imdsV2ServerHeaderIdentifier = "IMDS"
)

// cuidInfo is the compute unique identifier IMDS reports for this host. Exactly
// one of the two fields is populated: VMID for a standalone VM and VMSSID for a
// scale set member.
//
// These names are camelCase because that is what /getplatformmetadata returns.
//
// Both fields are omitempty because this value is echoed back inside the signed
// CSR attribute and IMDS validates it against what it issued. A standalone VM
// gets {"vmId":"..."} with no vmssId member at all, so emitting an empty vmssId
// makes the service reject the CSR.
type cuidInfo struct {
	VMID   string `json:"vmId,omitempty"`
	VMSSID string `json:"vmssId,omitempty"`
}

func (c cuidInfo) isEmpty() bool {
	return c.VMID == "" && c.VMSSID == ""
}

// csrMetadata is the /getplatformmetadata response.
//
// Note the casing: this endpoint answers in camelCase while /issuecredential
// answers in snake_case. The two are genuinely inconsistent, so the struct tags
// here and on certificateRequestResponse must not be made uniform.
type csrMetadata struct {
	CuID                cuidInfo `json:"cuId"`
	ClientID            string   `json:"clientId"`
	TenantID            string   `json:"tenantId"`
	AttestationEndpoint string   `json:"attestationEndpoint"`
}

func (m csrMetadata) validate() error {
	// Presence first, so a missing field is reported as missing rather than as
	// a malformed one. Every field is required before any is inspected.
	switch {
	case m.ClientID == "":
		return fmt.Errorf("managedidentity: IMDS returned platform metadata without a clientId")
	case m.TenantID == "":
		return fmt.Errorf("managedidentity: IMDS returned platform metadata without a tenantId")
	case m.CuID.isEmpty():
		return fmt.Errorf("managedidentity: IMDS returned platform metadata without a vmId or vmssId")
	case m.AttestationEndpoint == "":
		// Required even when this acquisition will not attest, because MSAL .NET
		// rejects the metadata document outright in that case
		// (CsrMetadata.ValidateCsrMetadata). A host that omits the field is
		// misconfigured for every caller, not only the attesting one, so both
		// libraries should refuse it at the same point.
		return fmt.Errorf("managedidentity: IMDS returned platform metadata with no attestationEndpoint")
	}
	// Both identifiers are GUIDs, and both are load-bearing well past this
	// document: the client ID becomes the CSR subject, the client_id of the
	// token request and half of the persisted certificate's identity check,
	// while the tenant ID is spliced into the token endpoint path and the
	// persisted certificate's friendly name. Checking the shape is what stops an
	// unauthenticated responder on the link-local address from steering any of
	// them with a value that is not an identifier at all.
	if !looksLikeGUID(m.ClientID) {
		return fmt.Errorf("managedidentity: IMDS returned platform metadata whose clientId %q is not a GUID", m.ClientID)
	}
	if !looksLikeGUID(m.TenantID) {
		return fmt.Errorf("managedidentity: IMDS returned platform metadata whose tenantId %q is not a GUID", m.TenantID)
	}
	return nil
}

// looksLikeGUID reports whether s is a bare 8-4-4-4-12 hexadecimal GUID.
//
// A managed identity client ID and an Entra tenant ID are both GUIDs, and both
// reach places where a free-form string would be damaging: a cache partition
// key, a certificate subject, and the client_id of the token request. Checking
// the shape is what stops a spoofed metadata response from steering any of them
// with a value that is not an identifier at all. Braced and URN forms are
// deliberately not accepted, because neither service emits them and accepting
// both spellings would give one identity two cache keys.
func looksLikeGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}

// imdsV2AllowedHostsEnvVar pins the hosts IMDS is allowed to name for the two
// credential-bearing destinations it reports: the attestation endpoint and the
// mTLS token endpoint.
//
// Legs 1 and 2 are unauthenticated plain HTTP to a link-local address, so both
// of those hosts arrive from an unauthenticated source. There is no cloud
// metadata in this package to derive a default from - a managed identity Client
// is built against a fixed placeholder authority, so it does not know which
// cloud it is in - and a built-in list of public-cloud suffixes would break
// every sovereign, Arc-connected and private deployment the moment a region was
// added. So the list is left to the operator, who does know.
//
// Unset, which is the default, means IMDS is trusted for these values exactly as
// it was before: leg 1 is the trust boundary, an attestation statement is only
// useful to the endpoint that issued it, and a token is only useful if Entra
// signed it. Set, it is a fail-closed allowlist: an endpoint whose host is not
// named is refused before anything is sent to it.
//
// The value is a comma or semicolon separated list of hosts. A leading "*." is a
// suffix match over whole labels, so "*.example.com" admits "a.example.com" and
// "example.com" but not "notexample.com". Matching is case-insensitive and
// ignores any port.
const imdsV2AllowedHostsEnvVar = "MSAL_MI_IMDSV2_ALLOWED_HOSTS"

// allowedIMDSv2Hosts reads the operator's allowlist. An empty result means no
// restriction was configured.
func allowedIMDSv2Hosts() []string {
	raw := os.Getenv(imdsV2AllowedHostsEnvVar)
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' }) {
		if p := strings.ToLower(strings.TrimSpace(part)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// checkIMDSv2HostAllowed enforces the allowlist, if one is configured, against a
// host IMDS reported. what names the endpoint in the error, so an operator who
// set the list too narrowly can see which of the two was refused.
func checkIMDSv2HostAllowed(what, host string) error {
	patterns := allowedIMDSv2Hosts()
	if len(patterns) == 0 {
		return nil
	}
	h := strings.ToLower(strings.TrimSpace(host))
	for _, pattern := range patterns {
		if suffix := strings.TrimPrefix(pattern, "*."); suffix != pattern {
			if h == suffix || strings.HasSuffix(h, "."+suffix) {
				return nil
			}
			continue
		}
		if h == pattern {
			return nil
		}
	}
	return fmt.Errorf("managedidentity: IMDS named %s host %q, which is not in %s", what, host, imdsV2AllowedHostsEnvVar)
}

// attestationURL returns the attestation endpoint to hand to the native
// library. Legs 1 and 2 are plain HTTP and are not authenticated, so the value
// is validated before use for the same reason [bindingCertificate.tokenEndpoint]
// validates the token endpoint: a compromised or spoofed IMDS response must not
// be able to redirect attestation to an endpoint of the attacker's choosing, or
// downgrade it to plaintext. The native library fetches its own managed identity
// token for this call, so the endpoint is a credential-bearing destination.
//
// The origin is rebuilt from the parsed host rather than returning the string
// that was validated. The native library parses this URL again with C++ rules,
// and a string can parse differently there than it does in net/url: Go reads
// the host of "https:/\/\example.com" as "https", while a parser that folds
// backslashes to slashes reads it as "example.com". Returning only scheme and
// host means the endpoint that was checked is byte-for-byte the endpoint that
// is used. MAA endpoints are bare origins, so nothing is lost by dropping any
// path, query or fragment.
//
// Validation stops at the origin unless an operator has said otherwise. The
// host itself is whatever IMDS said, and is deliberately not checked against a
// built-in list of known MAA hosts: such a list would have to track every
// sovereign and Arc-connected cloud, this package has no cloud metadata to
// derive one from, and it would fail closed on any new region before the list
// caught up. An attestation statement is only useful to the endpoint that
// issued it, and the token the native library sends is scoped to the attestation
// audience, so a redirected call cannot be replayed at a resource. Leg 1 is the
// trust boundary for this value. A deployment that wants a narrower one names
// its own hosts in MSAL_MI_IMDSV2_ALLOWED_HOSTS, which is enforced here.
func (m csrMetadata) attestationURL() (string, error) {
	if m.AttestationEndpoint == "" {
		return "", fmt.Errorf("managedidentity: attestation was requested but IMDS returned no attestationEndpoint")
	}
	raw := strings.TrimSuffix(m.AttestationEndpoint, "/")
	// A backslash is never part of a URL authority, and every parser that
	// disagrees does so in the attacker's favour: C++ URL parsers fold it to a
	// slash, so "https:/\/\attacker.example" names attacker.example to them
	// while net/url reads no authority there at all. Rejecting it outright is
	// the only reading both parsers can agree on.
	if strings.Contains(raw, `\`) {
		return "", fmt.Errorf("managedidentity: IMDS returned an attestation endpoint with a backslash in it %q", m.AttestationEndpoint)
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("managedidentity: IMDS returned an unusable attestation endpoint %q: %w", m.AttestationEndpoint, err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("managedidentity: IMDS returned a non-https attestation endpoint %q", m.AttestationEndpoint)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("managedidentity: IMDS returned an attestation endpoint with no host %q", m.AttestationEndpoint)
	}
	// A colon in the authority with nothing usable after it means it never
	// parsed as an authority. "https:/nonsense" reaches here as a host of
	// "https:" because the value carries no "://" and so had a second scheme
	// prepended; returning it would hand a malformed origin to the native
	// parser.
	if u.Port() == "" && strings.Contains(u.Host, ":") {
		return "", fmt.Errorf("managedidentity: IMDS returned an attestation endpoint with a malformed authority %q", m.AttestationEndpoint)
	}
	// Userinfo makes the authority read one way to a person and another to a
	// resolver: "https://attestation.example@attacker.example" resolves to
	// attacker.example while looking like the real endpoint in a log. No MAA
	// endpoint has it, so its presence is only ever an attempt to disguise one.
	if u.User != nil {
		return "", fmt.Errorf("managedidentity: IMDS returned an attestation endpoint with userinfo in it %q", m.AttestationEndpoint)
	}
	if err := checkIMDSv2HostAllowed("attestation endpoint", u.Hostname()); err != nil {
		return "", err
	}
	return "https://" + u.Host, nil
}

// certificateRequestBody is the /issuecredential request. AttestationToken is
// omitted entirely when attestation is not in use, which is what IMDS expects
// for a non-attested request.
type certificateRequestBody struct {
	CSR              string `json:"csr"`
	AttestationToken string `json:"attestation_token,omitempty"`
}

// certificateRequestResponse is the /issuecredential response.
//
// Unlike csrMetadata, this endpoint uses snake_case. See the note there.
type certificateRequestResponse struct {
	ClientID                   string `json:"client_id"`
	TenantID                   string `json:"tenant_id"`
	Certificate                string `json:"certificate"`
	IdentityType               string `json:"identity_type"`
	MtlsAuthenticationEndpoint string `json:"mtls_authentication_endpoint"`
}

func (r certificateRequestResponse) validate() error {
	missing := make([]string, 0, 5)
	if r.ClientID == "" {
		missing = append(missing, "client_id")
	}
	if r.TenantID == "" {
		missing = append(missing, "tenant_id")
	}
	if r.Certificate == "" {
		missing = append(missing, "certificate")
	}
	if r.IdentityType == "" {
		missing = append(missing, "identity_type")
	}
	if r.MtlsAuthenticationEndpoint == "" {
		missing = append(missing, "mtls_authentication_endpoint")
	}
	if len(missing) > 0 {
		return fmt.Errorf("managedidentity: IMDS issued a credential response missing %s", strings.Join(missing, ", "))
	}
	// Both identifiers are GUIDs, and both are load-bearing beyond this
	// response: the client ID becomes the client_id of the token request and
	// half of the persisted certificate's identity check, and the tenant ID is
	// spliced into the token endpoint path. Checking the shape before either is
	// used keeps a malformed or hostile value from reaching them.
	if !looksLikeGUID(r.ClientID) {
		return fmt.Errorf("managedidentity: IMDS issued a credential whose client_id %q is not a GUID", r.ClientID)
	}
	if !looksLikeGUID(r.TenantID) {
		return fmt.Errorf("managedidentity: IMDS issued a credential whose tenant_id %q is not a GUID", r.TenantID)
	}
	return nil
}

// validateAgainst checks that the credential IMDS issued belongs to the identity
// leg 1 named.
//
// Leg 1 is what decides which identity this acquisition is for: it is the value
// the CSR subject carries, the value the certificate cache was keyed on before
// the request went out, and the value the caller believes it is holding a
// credential for. A leg 2 response that names a different identity is therefore
// not a credential for this request, whether that is a service-side bug, a
// reassignment that happened between the two legs, or a spoofed responder on the
// link-local address. Either way it must not be used or persisted, because the
// certificate would be filed under one identity's cache key while naming
// another's.
func (r certificateRequestResponse) validateAgainst(metadata csrMetadata) error {
	if !strings.EqualFold(r.ClientID, metadata.ClientID) {
		return fmt.Errorf("managedidentity: IMDS issued a credential for client ID %q but the platform metadata named %q",
			r.ClientID, metadata.ClientID)
	}
	if !strings.EqualFold(r.TenantID, metadata.TenantID) {
		return fmt.Errorf("managedidentity: IMDS issued a credential for tenant %q but the platform metadata named %q",
			r.TenantID, metadata.TenantID)
	}
	return nil
}

// validateIMDSServerHeader rejects a response that does not look like it came
// from IMDS. This is a misrouting check, not a security control: the IMDS legs
// are unauthenticated plain HTTP to a link-local address, so anything that can
// answer on that address can also set this header. What it catches is a proxy,
// a captive portal or an unrelated local listener answering on 169.254.169.254,
// which otherwise surfaces as a confusing parse failure further along.
//
// The protections that do hold against a hostile responder are elsewhere: the
// issued certificate must carry the public half of the VBS key
// ([certificateMatchesKey]), and any token ultimately has to be signed
// by Entra to be accepted by a resource.
func validateIMDSServerHeader(resp *http.Response) error {
	server := resp.Header.Get(imdsV2ServerHeader)
	if server == "" {
		return fmt.Errorf("managedidentity: the IMDS response has no %s header", imdsV2ServerHeader)
	}
	if !strings.Contains(strings.ToUpper(server), imdsV2ServerHeaderIdentifier) {
		return fmt.Errorf("managedidentity: the IMDS response came from an unexpected server %q", server)
	}
	return nil
}

// imdsErrorResponse is the error shape both IMDS legs use.
//
// IMDS is not consistent about which fields it fills. The OAuth-style pair is
// the documented shape, but some failures answer with a bare "message" instead,
// and most carry a correlationId that is the only handle a support engineer can
// use to find the request in the service's own logs. MSAL .NET reads all of
// them (ManagedIdentityErrorResponse: Message, Error, ErrorDescription,
// CorrelationId), so a Go caller filing the same incident has the same
// identifier to quote.
type imdsErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	Message          string `json:"message"`
	CorrelationID    string `json:"correlationId"`
}

func (e imdsErrorResponse) String() string {
	var s string
	switch {
	case e.Error != "" && e.ErrorDescription != "":
		s = fmt.Sprintf("%s: %s", e.Error, e.ErrorDescription)
	case e.Error != "":
		s = e.Error
	case e.ErrorDescription != "":
		s = e.ErrorDescription
	default:
		s = e.Message
	}
	if s == "" {
		return ""
	}
	if e.CorrelationID != "" {
		s = fmt.Sprintf("%s (correlation ID %s)", s, e.CorrelationID)
	}
	return s
}

// parseIMDSError extracts the error payload IMDS returns on a non-200. The body
// is best effort: IMDS is not guaranteed to return JSON for every failure.
func parseIMDSError(body []byte) string {
	var e imdsErrorResponse
	if err := json.Unmarshal(body, &e); err == nil {
		if s := e.String(); s != "" {
			return s
		}
	}
	return strings.TrimSpace(string(body))
}

// entraTokenError is a non-200 from the Entra token endpoint on the mTLS leg.
// The OAuth error code is kept because invalid_client specifically means the
// binding certificate is no longer acceptable, which is recoverable by minting
// a new one.
type entraTokenError struct {
	StatusCode  int
	Code        string
	Description string
}

func (e *entraTokenError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("managedidentity: the token endpoint returned %d: %s: %s", e.StatusCode, e.Code, e.Description)
	}
	if e.Code != "" {
		return fmt.Sprintf("managedidentity: the token endpoint returned %d: %s", e.StatusCode, e.Code)
	}
	return fmt.Sprintf("managedidentity: the token endpoint returned %d", e.StatusCode)
}

// newEntraTokenError builds an error from an Entra token endpoint failure.
func newEntraTokenError(statusCode int, body []byte) error {
	e := &entraTokenError{StatusCode: statusCode}
	var parsed imdsErrorResponse
	if err := json.Unmarshal(body, &parsed); err == nil {
		e.Code = parsed.Error
		e.Description = parsed.ErrorDescription
	}
	if e.Code == "" && e.Description == "" && len(body) > 0 {
		e.Description = strings.TrimSpace(string(body))
	}
	return e
}

// shouldRemintCertificate reports whether err indicates the binding certificate
// itself is the problem, rather than the request being wrong.
//
// Three things mean that. Entra answers invalid_client when it no longer accepts
// the certificate. The TLS stack raises a certificate-specific alert when the
// server rejects the client certificate before any HTTP response exists to carry
// an error code. And our own signer reports that the binding key can no longer
// sign. Each is fixed by minting a new certificate, and none is fixed by
// retrying with the same one.
//
// Everything else is deliberately excluded, because re-minting is not free: it
// discards a valid certificate, deletes the persisted copy shared with MSAL
// .NET, and spends an /issuecredential call against a rate-limited service. A
// bare connection reset is the clearest example. It is what a proxy, a firewall,
// an idle pooled connection, a load balancer draining, or a service restart all
// produce, and none of those says anything about the certificate; treating it as
// a rejection means a network blip rotates a healthy machine credential, and a
// persistent one rotates it on every attempt. A server that genuinely refuses
// the certificate has a TLS alert for saying so, and that is what is matched.
//
// bindingKeySignFailureMarker appears on every failure that means the key
// itself can no longer sign: a closed key, or either NCryptSignHash call. The
// signer's three argument checks - a nil SignerOpts, a digest whose length
// disagrees with the hash, and a hash CNG has no name for - deliberately omit
// it, because they report a caller mistake that a new certificate would not
// fix. crypto/tls cannot produce any of them: it always supplies opts, sizes
// the digest from the hash it passes, and negotiates only SHA-256, SHA-384 or
// SHA-512 for RSA, every one of which algorithmIdentifier accepts.
//
// A certificate is worth nothing once the private key behind it can no longer
// sign, and that happens for reasons the server never sees: the isolated
// container is reset, or a handle is closed while a cached TLS client still
// holds it. The failure then surfaces inside the handshake as our own signing
// error, so unless it is recognised the client keeps presenting the same dead
// certificate for the life of the process.
//
// It has to be matched as text. crypto/tls reports the failure as
// "tls: failed to sign handshake: " + err.Error(), a concatenation rather than a
// wrapped error, so the chain - and any sentinel in it - is gone by the time the
// caller sees the failure. This is the same fallback certificateAlertText relies
// on for TLS alerts.
const bindingKeySignFailureMarker = "managedidentity: the binding key cannot sign"

func shouldRemintCertificate(err error) bool {
	if err == nil {
		return false
	}
	var tokenErr *entraTokenError
	if errors.As(err, &tokenErr) {
		return tokenErr.Code == "invalid_client"
	}
	if strings.Contains(err.Error(), bindingKeySignFailureMarker) {
		return true
	}
	// A failure to verify the server's own chain is deliberately not treated as
	// re-mintable either: our certificate is not the problem, and silently
	// retrying would obscure an untrusted or intercepted endpoint.
	return isCertificateAlert(err)
}

// certificateAlertText reports whether the error message describes a TLS alert
// that names the client certificate as the reason the handshake failed.
//
// This is the fallback for toolchains that predate the typed alert; see
// isCertificateAlert. It is deliberately kept next to the typed implementation
// so the two sets of alerts stay in step, and like that one it lists only alerts
// that name a certificate: a bare handshake_failure is what a server sends for a
// protocol version or cipher suite it cannot agree on, so matching it would
// rotate the credential over a TLS configuration problem.
func certificateAlertText(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, alert := range []string{
		"tls: bad certificate",
		"tls: certificate required",
		"tls: revoked certificate",
		"tls: expired certificate",
		"tls: unknown certificate",
		"tls: unsupported certificate",
		"tls: unknown certificate authority",
		"tls: access denied",
	} {
		if strings.Contains(msg, alert) {
			return true
		}
	}
	return false
}
