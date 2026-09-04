// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"syscall"
)

// wsaeConnReset is WSAECONNRESET. Windows reports a peer-side connection reset
// with this Winsock code rather than the POSIX ECONNRESET value.
const wsaeConnReset = 10054

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
	return nil
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
// Validation stops at the origin: the host itself is whatever IMDS said, and is
// deliberately not checked against a list of known MAA hosts. Such a list would
// have to track every sovereign and Arc-connected cloud, and would fail closed
// on any new region before the list caught up. An attestation statement is only
// useful to the endpoint that issued it, and the token the native library sends
// is scoped to the attestation audience, so a redirected call cannot be replayed
// at a resource. Leg 1 is the trust boundary for this value.
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
// Two things mean the same thing here. Entra answers invalid_client when it no
// longer accepts the certificate. The TLS stack answers with a connection reset
// or a handshake failure when the server rejects the client certificate before
// any HTTP response exists to carry an error code. Both are fixed by minting a
// new certificate, and neither is fixed by retrying with the same one.
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
	// re-mintable: our certificate is not the problem, and silently retrying
	// would obscure an untrusted or intercepted endpoint.
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	// Windows reports the same condition with its own code rather than ECONNRESET.
	var errno syscall.Errno
	if errors.As(err, &errno) && uintptr(errno) == wsaeConnReset {
		return true
	}
	return isCertificateAlert(err)
}

// certificateAlertText reports whether the error message describes a TLS alert
// that names the client certificate as the reason the handshake failed.
//
// This is the fallback for toolchains that predate the typed alert; see
// isCertificateAlert. It is deliberately kept next to the typed implementation
// so the two sets of alerts stay in step.
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
		"tls: handshake failure",
		"handshake failure",
	} {
		if strings.Contains(msg, alert) {
			return true
		}
	}
	return false
}
