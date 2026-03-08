// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package models defines the request and response types for the MSI v2
// seven-step credential flow. Each type documents which fields from a prior
// response feed into the next request so that the data-dependency chain is
// explicit and type-safe.
//
// Seven-step flow summary:
//
//	Step 1 – KeyGuard key creation (platform-level, no network call)
//	Step 2 – IMDS platform-metadata request  → IMDSPlatformMetadataResponse
//	Step 3 – CSR generation using fields from Step 2 → CSRInfo
//	Step 4 – MAA attestation                 → MAAAttestationResponse
//	Step 5 – IMDS credential issuance        → IMDSCredentialResponse
//	Step 6 – ESTS mTLS-PoP token request     → EstsTokenResponse
//	Step 7 – Resource call with mTLS PoP     → ResourceCallResponse
package models

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Step 2 – IMDS Platform Metadata
// ---------------------------------------------------------------------------

// IMDSPlatformMetadataRequest represents the GET request sent to the IMDS
// platform-metadata endpoint.
//
//	GET /metadata/identity/getplatformmetadata?cred-api-version=2.0
//	Metadata: true
type IMDSPlatformMetadataRequest struct {
	// APIVersion is the cred-api-version query-parameter value (e.g. "2.0").
	APIVersion string
}

// IMDSPlatformMetadataResponse is the JSON body returned by the IMDS
// platform-metadata endpoint (Step 2).  The fields below feed directly into
// subsequent steps:
//
//   - ClientID            → Step 5 (IMDSCredentialRequest) and Step 6 (EstsTokenRequest)
//   - TenantID            → Step 3 (CSRInfo) and Step 6 (EstsTokenRequest)
//   - CUID                → Step 3 (CSRInfo)
//   - AttestationEndpoint → Step 4 (MAAAttestationRequest)
type IMDSPlatformMetadataResponse struct {
	// ClientID is the managed-identity client ID assigned to this resource.
	// Feeds into: Step 5 IMDSCredentialRequest, Step 6 EstsTokenRequest.
	ClientID string `json:"clientId"`

	// TenantID is the Azure AD tenant that owns this managed identity.
	// Feeds into: Step 3 CSRInfo, Step 6 EstsTokenRequest.
	TenantID string `json:"tenantId"`

	// CUID (Cryptographic Unit ID) is an opaque object used when building the
	// certificate signing request in Step 3.
	// Feeds into: Step 3 CSRInfo.
	CUID map[string]interface{} `json:"cuId"`

	// AttestationEndpoint is the MAA endpoint URL.
	// Feeds into: Step 4 MAAAttestationRequest URL.
	AttestationEndpoint string `json:"attestationEndpoint"`
}

// Validate returns an error if any required field is missing.
func (r *IMDSPlatformMetadataResponse) Validate() error {
	var errs []string
	if r.ClientID == "" {
		errs = append(errs, "clientId")
	}
	if r.TenantID == "" {
		errs = append(errs, "tenantId")
	}
	if r.AttestationEndpoint == "" {
		errs = append(errs, "attestationEndpoint")
	}
	if len(errs) > 0 {
		return fmt.Errorf("IMDSPlatformMetadataResponse missing required fields: %s", strings.Join(errs, ", "))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Step 3 – CSR Generation helper
// ---------------------------------------------------------------------------

// CSRInfo bundles the IMDS metadata fields that are needed to construct the
// certificate signing request (Step 3).  All fields come from
// IMDSPlatformMetadataResponse (Step 2).
type CSRInfo struct {
	// ClientID comes from IMDSPlatformMetadataResponse.ClientID.
	ClientID string

	// TenantID comes from IMDSPlatformMetadataResponse.TenantID.
	TenantID string

	// CUID comes from IMDSPlatformMetadataResponse.CUID.
	CUID map[string]interface{}
}

// NewCSRInfo creates a CSRInfo from an IMDSPlatformMetadataResponse.
func NewCSRInfo(meta *IMDSPlatformMetadataResponse) (*CSRInfo, error) {
	if meta == nil {
		return nil, errors.New("IMDSPlatformMetadataResponse must not be nil")
	}
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	return &CSRInfo{
		ClientID: meta.ClientID,
		TenantID: meta.TenantID,
		CUID:     meta.CUID,
	}, nil
}

// ---------------------------------------------------------------------------
// Step 4 – MAA Attestation
// ---------------------------------------------------------------------------

// MAAAttestationRequest is the JSON body posted to the MAA attestation
// endpoint.  The endpoint URL itself comes from
// IMDSPlatformMetadataResponse.AttestationEndpoint (Step 2).
//
//	POST {attestationEndpoint}
type MAAAttestationRequest struct {
	// CSRPayload is the base64url-encoded certificate signing request generated
	// in Step 3.
	CSRPayload string `json:"csrPayload"`

	// KeyHandle is the opaque handle returned by the KeyGuard key-creation
	// operation (Step 1).
	KeyHandle string `json:"keyHandle"`
}

// Validate returns an error if any required field is missing.
func (r *MAAAttestationRequest) Validate() error {
	var errs []string
	if r.CSRPayload == "" {
		errs = append(errs, "csrPayload")
	}
	if r.KeyHandle == "" {
		errs = append(errs, "keyHandle")
	}
	if len(errs) > 0 {
		return fmt.Errorf("MAAAttestationRequest missing required fields: %s", strings.Join(errs, ", "))
	}
	return nil
}

// MAAAttestationResponse is the JSON body returned by the MAA attestation
// endpoint (Step 4).
//
//   - AttestationToken → Step 5 IMDSCredentialRequest
type MAAAttestationResponse struct {
	// AttestationToken is a signed JWT issued by MAA that proves the hardware
	// attestation succeeded.
	// Feeds into: Step 5 IMDSCredentialRequest.AttestationToken.
	AttestationToken string `json:"attestation_token"`
}

// Validate returns an error if AttestationToken is empty.
func (r *MAAAttestationResponse) Validate() error {
	if r.AttestationToken == "" {
		return errors.New("MAAAttestationResponse missing required field: attestation_token")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Step 5 – IMDS Credential Issuance
// ---------------------------------------------------------------------------

// IMDSCredentialRequest is the JSON body posted to the IMDS credential
// endpoint.
//
//	POST /metadata/identity/issuecredential?cred-api-version=2.0
//	Metadata: true
//
// Both fields come from prior steps:
//   - CSR is generated in Step 3.
//   - AttestationToken comes from MAAAttestationResponse (Step 4).
type IMDSCredentialRequest struct {
	// CSR is the base64url-encoded certificate signing request (Step 3 output).
	CSR string `json:"csr"`

	// AttestationToken comes from MAAAttestationResponse.AttestationToken (Step 4).
	AttestationToken string `json:"attestation_token"`
}

// Validate returns an error if any required field is missing.
func (r *IMDSCredentialRequest) Validate() error {
	var errs []string
	if r.CSR == "" {
		errs = append(errs, "csr")
	}
	if r.AttestationToken == "" {
		errs = append(errs, "attestation_token")
	}
	if len(errs) > 0 {
		return fmt.Errorf("IMDSCredentialRequest missing required fields: %s", strings.Join(errs, ", "))
	}
	return nil
}

// IMDSCredentialResponse is the JSON body returned by the IMDS credential
// endpoint (Step 5).  Its fields feed directly into the ESTS token request
// (Step 6):
//
//   - Certificate                → Step 6 TLS client certificate
//   - MtlsAuthenticationEndpoint → Step 6 token endpoint base URL
//   - TokenEndpoint              → Step 6 token endpoint (optional override)
//   - TenantID                   → Step 6 EstsTokenRequest
//   - ClientID                   → Step 6 EstsTokenRequest
type IMDSCredentialResponse struct {
	// Certificate is a base64-encoded DER certificate issued to this identity.
	// Feeds into: Step 6 mTLS client certificate.
	Certificate string `json:"certificate"`

	// MtlsAuthenticationEndpoint is the mTLS-capable token endpoint base URL.
	// Feeds into: Step 6 EstsTokenRequest URL (combined with TenantID when
	// TokenEndpoint is empty).
	MtlsAuthenticationEndpoint string `json:"mtls_authentication_endpoint"`

	// TokenEndpoint is an optional direct token endpoint URL.  When present it
	// takes precedence over deriving the URL from MtlsAuthenticationEndpoint
	// and TenantID.
	// Feeds into: Step 6 EstsTokenRequest URL (if non-empty).
	TokenEndpoint string `json:"token_endpoint,omitempty"`

	// TenantID is the Azure AD tenant for this credential.
	// Feeds into: Step 6 EstsTokenRequest.
	TenantID string `json:"tenant_id"`

	// ClientID is the application/managed-identity client ID.
	// Feeds into: Step 6 EstsTokenRequest.ClientID.
	ClientID string `json:"client_id"`
}

// Validate returns an error if any required field is missing.
func (r *IMDSCredentialResponse) Validate() error {
	var errs []string
	if r.Certificate == "" {
		errs = append(errs, "certificate")
	}
	if r.MtlsAuthenticationEndpoint == "" {
		errs = append(errs, "mtls_authentication_endpoint")
	}
	if r.TenantID == "" {
		errs = append(errs, "tenant_id")
	}
	if r.ClientID == "" {
		errs = append(errs, "client_id")
	}
	if len(errs) > 0 {
		return fmt.Errorf("IMDSCredentialResponse missing required fields: %s", strings.Join(errs, ", "))
	}
	return nil
}

// ResolveTokenEndpoint returns the token endpoint URL to use for the ESTS
// token request (Step 6).  If TokenEndpoint is set it is returned directly;
// otherwise the endpoint is derived from MtlsAuthenticationEndpoint and
// TenantID using the standard OAuth2 path.
func (r *IMDSCredentialResponse) ResolveTokenEndpoint() (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	if r.TokenEndpoint != "" {
		return r.TokenEndpoint, nil
	}
	base := strings.TrimRight(r.MtlsAuthenticationEndpoint, "/")
	return fmt.Sprintf("%s/%s/oauth2/v2.0/token", base, r.TenantID), nil
}

// ---------------------------------------------------------------------------
// Step 6 – ESTS mTLS-PoP Token Request / Response
// ---------------------------------------------------------------------------

// EstsTokenRequest represents the form-encoded body posted to the ESTS token
// endpoint over a mutual TLS connection (Step 6).  All field values come from
// IMDSCredentialResponse (Step 5).
//
//	POST {credential.MtlsAuthenticationEndpoint}/{credential.TenantID}/oauth2/v2.0/token
//	TLS client cert: credential.Certificate
type EstsTokenRequest struct {
	// GrantType is always "client_credentials" for this flow.
	GrantType string `json:"grant_type"`

	// ClientID comes from IMDSCredentialResponse.ClientID (Step 5).
	ClientID string `json:"client_id"`

	// Scope is the resource scope requested by the caller (e.g. "https://.../.default").
	Scope string `json:"scope"`

	// TokenType must be "mtls_pop" to request a proof-of-possession token.
	TokenType string `json:"token_type"`
}

// Validate returns an error if any required field is missing.
func (r *EstsTokenRequest) Validate() error {
	var errs []string
	if r.GrantType == "" {
		errs = append(errs, "grant_type")
	}
	if r.ClientID == "" {
		errs = append(errs, "client_id")
	}
	if r.Scope == "" {
		errs = append(errs, "scope")
	}
	if r.TokenType == "" {
		errs = append(errs, "token_type")
	}
	if len(errs) > 0 {
		return fmt.Errorf("EstsTokenRequest missing required fields: %s", strings.Join(errs, ", "))
	}
	return nil
}

// EstsTokenResponse is the JSON body returned by the ESTS token endpoint
// (Step 6).  The AccessToken is a JWT containing a "cnf" claim whose
// "x5t#S256" field binds the token to the certificate used in Step 5.
//
//   - AccessToken → Step 7 Authorization header
type EstsTokenResponse struct {
	// AccessToken is a signed JWT issued by ESTS.  Its "cnf.x5t#S256" claim
	// is the SHA-256 thumbprint of the certificate from Step 5.
	// Feeds into: Step 7 ResourceCallRequest.Authorization.
	AccessToken string `json:"access_token"`

	// TokenType is the type of the access token (e.g. "mtls_pop").
	TokenType string `json:"token_type"`

	// ExpiresIn is the token lifetime in seconds.
	ExpiresIn int `json:"expires_in"`
}

// Validate returns an error if any required field is missing.
func (r *EstsTokenResponse) Validate() error {
	var errs []string
	if r.AccessToken == "" {
		errs = append(errs, "access_token")
	}
	if r.TokenType == "" {
		errs = append(errs, "token_type")
	}
	if len(errs) > 0 {
		return fmt.Errorf("EstsTokenResponse missing required fields: %s", strings.Join(errs, ", "))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Token Binding (cnf claim)
// ---------------------------------------------------------------------------

// TokenConfirmation represents the "cnf" (confirmation) claim embedded in
// mTLS-PoP access tokens.  It binds the token to a specific certificate.
type TokenConfirmation struct {
	// X5tS256 is the base64url-encoded SHA-256 thumbprint of the certificate
	// (raw DER bytes).  The field name uses the standard claim name "x5t#S256".
	X5tS256 string `json:"x5t#S256"`
}

// TokenClaims represents the subset of JWT claims relevant to mTLS-PoP token
// binding verification.
type TokenClaims struct {
	// Cnf holds the confirmation claim containing the certificate thumbprint.
	Cnf TokenConfirmation `json:"cnf"`

	// Subject is the subject claim (optional, for reference).
	Subject string `json:"sub,omitempty"`

	// Issuer is the issuer claim (optional, for reference).
	Issuer string `json:"iss,omitempty"`

	// ExpirationTime is the "exp" claim (Unix timestamp).
	ExpirationTime int64 `json:"exp,omitempty"`
}

// TokenBinding provides helpers for verifying the cnf.x5t#S256 binding
// between an access token and the client certificate used in Step 5 / Step 6.
type TokenBinding struct {
	// CertDER is the raw DER-encoded bytes of the client certificate (decoded
	// from IMDSCredentialResponse.Certificate).
	CertDER []byte
}

// Thumbprint returns the base64url-encoded SHA-256 digest of CertDER.
func (tb *TokenBinding) Thumbprint() string {
	sum := sha256.Sum256(tb.CertDER)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyToken parses the claims in accessToken (a compact JWT) and returns an
// error if the cnf.x5t#S256 claim does not match the certificate thumbprint.
func (tb *TokenBinding) VerifyToken(accessToken string) error {
	claims, err := parseJWTClaims(accessToken)
	if err != nil {
		return fmt.Errorf("token binding verification failed: %w", err)
	}
	expected := tb.Thumbprint()
	if claims.Cnf.X5tS256 != expected {
		return fmt.Errorf("token binding mismatch: token x5t#S256 %q does not match certificate thumbprint %q",
			claims.Cnf.X5tS256, expected)
	}
	return nil
}

// parseJWTClaims decodes the claims section of a compact JWT without
// verifying the signature.  It is used solely for extracting the cnf claim.
func parseJWTClaims(token string) (*TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format: expected 3 parts")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}
	var claims TokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT claims: %w", err)
	}
	return &claims, nil
}

// ---------------------------------------------------------------------------
// Step 7 – Resource Call with mTLS PoP
// ---------------------------------------------------------------------------

// ResourceCallRequest describes the outbound resource request (Step 7).
// Both the access token and the TLS certificate come from earlier steps.
//
//	POST/GET {ResourceURL}
//	Authorization: mtls_pop <AccessToken>
//	TLS client cert: Certificate (same as Step 6)
type ResourceCallRequest struct {
	// ResourceURL is the URL of the protected resource.
	ResourceURL string

	// AccessToken comes from EstsTokenResponse.AccessToken (Step 6).
	// Used as: Authorization: mtls_pop <AccessToken>
	AccessToken string

	// Certificate is the same DER-encoded certificate used in Step 6.
	// Used for mTLS client authentication on the resource connection.
	Certificate []byte
}

// Validate returns an error if any required field is missing.
func (r *ResourceCallRequest) Validate() error {
	var errs []string
	if r.ResourceURL == "" {
		errs = append(errs, "ResourceURL")
	}
	if r.AccessToken == "" {
		errs = append(errs, "AccessToken")
	}
	if len(r.Certificate) == 0 {
		errs = append(errs, "Certificate")
	}
	if len(errs) > 0 {
		return fmt.Errorf("ResourceCallRequest missing required fields: %s", strings.Join(errs, ", "))
	}
	return nil
}

// ResourceCallResponse represents the response received from the protected
// resource endpoint (Step 7).
type ResourceCallResponse struct {
	// StatusCode is the HTTP status code returned by the resource.
	StatusCode int

	// Body contains the raw response body.
	Body []byte
}

// ---------------------------------------------------------------------------
// Error Models
// ---------------------------------------------------------------------------

// IMDSError represents an error response from the IMDS endpoint.
type IMDSError struct {
	// StatusCode is the HTTP status code (e.g. 400, 404, 500).
	StatusCode int

	// Code is the error code string returned in the JSON body (JSON field: "error").
	Code string `json:"error"`

	// ErrorDescription is the human-readable error description.
	ErrorDescription string `json:"error_description"`
}

// Error implements the error interface.
func (e *IMDSError) Error() string { return e.ErrorMessage() }

// ErrorMessage returns a formatted error string with the status code, error
// code and description.
func (e *IMDSError) ErrorMessage() string {
	return fmt.Sprintf("IMDS error %d: %s – %s", e.StatusCode, e.Code, e.ErrorDescription)
}

// MAAError represents an error response from the MAA attestation endpoint.
type MAAError struct {
	// StatusCode is the HTTP status code.
	StatusCode int

	// Code is the error code string (JSON field: "error").
	Code string `json:"error"`

	// ErrorDescription is the human-readable error description.
	ErrorDescription string `json:"error_description"`
}

// Error implements the error interface.
func (e *MAAError) Error() string { return e.ErrorMessage() }

// ErrorMessage returns a formatted error string with the status code, error
// code and description.
func (e *MAAError) ErrorMessage() string {
	return fmt.Sprintf("MAA error %d: %s – %s", e.StatusCode, e.Code, e.ErrorDescription)
}

// EstsError represents an error response from the ESTS token endpoint.
type EstsError struct {
	// StatusCode is the HTTP status code.
	StatusCode int

	// Code is the OAuth2 error code (e.g. "invalid_client") (JSON field: "error").
	Code string `json:"error"`

	// ErrorDescription is the human-readable error description.
	ErrorDescription string `json:"error_description"`

	// CorrelationID may be set by ESTS to help with diagnostics.
	CorrelationID string `json:"correlation_id,omitempty"`
}

// Error implements the error interface.
func (e *EstsError) Error() string { return e.ErrorMessage() }

// ErrorMessage returns a formatted error string with the status code, error
// code, description and correlation ID.
func (e *EstsError) ErrorMessage() string {
	return fmt.Sprintf("ESTS error %d: %s – %s (correlationId: %s)",
		e.StatusCode, e.Code, e.ErrorDescription, e.CorrelationID)
}
