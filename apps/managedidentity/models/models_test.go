// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package models

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// IMDSPlatformMetadataResponse tests
// ---------------------------------------------------------------------------

func TestIMDSPlatformMetadataResponse_Validate(t *testing.T) {
	tests := []struct {
		name    string
		resp    IMDSPlatformMetadataResponse
		wantErr bool
	}{
		{
			name: "valid response",
			resp: IMDSPlatformMetadataResponse{
				ClientID:            "client-id",
				TenantID:            "tenant-id",
				AttestationEndpoint: "https://maa.azure.net",
				CUID:                map[string]interface{}{"key": "value"},
			},
			wantErr: false,
		},
		{
			name:    "missing clientId",
			resp:    IMDSPlatformMetadataResponse{TenantID: "t", AttestationEndpoint: "https://maa.azure.net"},
			wantErr: true,
		},
		{
			name:    "missing tenantId",
			resp:    IMDSPlatformMetadataResponse{ClientID: "c", AttestationEndpoint: "https://maa.azure.net"},
			wantErr: true,
		},
		{
			name:    "missing attestationEndpoint",
			resp:    IMDSPlatformMetadataResponse{ClientID: "c", TenantID: "t"},
			wantErr: true,
		},
		{
			name:    "all empty",
			resp:    IMDSPlatformMetadataResponse{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.resp.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIMDSPlatformMetadataResponse_JSONRoundTrip(t *testing.T) {
	raw := `{"clientId":"cid","tenantId":"tid","cuId":{"k":"v"},"attestationEndpoint":"https://maa.azure.net"}`
	var resp IMDSPlatformMetadataResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if resp.ClientID != "cid" {
		t.Errorf("ClientID = %q, want %q", resp.ClientID, "cid")
	}
	if resp.TenantID != "tid" {
		t.Errorf("TenantID = %q, want %q", resp.TenantID, "tid")
	}
	if resp.AttestationEndpoint != "https://maa.azure.net" {
		t.Errorf("AttestationEndpoint = %q, want %q", resp.AttestationEndpoint, "https://maa.azure.net")
	}
	if resp.CUID["k"] != "v" {
		t.Errorf("CUID[\"k\"] = %v, want %q", resp.CUID["k"], "v")
	}
}

// ---------------------------------------------------------------------------
// CSRInfo tests
// ---------------------------------------------------------------------------

func TestNewCSRInfo(t *testing.T) {
	meta := &IMDSPlatformMetadataResponse{
		ClientID:            "cid",
		TenantID:            "tid",
		AttestationEndpoint: "https://maa.azure.net",
		CUID:                map[string]interface{}{"key": "val"},
	}
	info, err := NewCSRInfo(meta)
	if err != nil {
		t.Fatalf("NewCSRInfo: %v", err)
	}
	if info.ClientID != meta.ClientID {
		t.Errorf("ClientID = %q, want %q", info.ClientID, meta.ClientID)
	}
	if info.TenantID != meta.TenantID {
		t.Errorf("TenantID = %q, want %q", info.TenantID, meta.TenantID)
	}
}

func TestNewCSRInfo_NilMetadata(t *testing.T) {
	_, err := NewCSRInfo(nil)
	if err == nil {
		t.Error("expected error for nil metadata, got nil")
	}
}

func TestNewCSRInfo_InvalidMetadata(t *testing.T) {
	meta := &IMDSPlatformMetadataResponse{} // missing required fields
	_, err := NewCSRInfo(meta)
	if err == nil {
		t.Error("expected error for invalid metadata, got nil")
	}
}

// ---------------------------------------------------------------------------
// MAAAttestationRequest tests
// ---------------------------------------------------------------------------

func TestMAAAttestationRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     MAAAttestationRequest
		wantErr bool
	}{
		{
			name:    "valid",
			req:     MAAAttestationRequest{CSRPayload: "csr", KeyHandle: "kh"},
			wantErr: false,
		},
		{
			name:    "missing csrPayload",
			req:     MAAAttestationRequest{KeyHandle: "kh"},
			wantErr: true,
		},
		{
			name:    "missing keyHandle",
			req:     MAAAttestationRequest{CSRPayload: "csr"},
			wantErr: true,
		},
		{
			name:    "both missing",
			req:     MAAAttestationRequest{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMAAAttestationResponse_Validate(t *testing.T) {
	if err := (&MAAAttestationResponse{AttestationToken: "tok"}).Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := (&MAAAttestationResponse{}).Validate(); err == nil {
		t.Error("expected error for empty AttestationToken")
	}
}

// ---------------------------------------------------------------------------
// IMDSCredentialRequest tests
// ---------------------------------------------------------------------------

func TestIMDSCredentialRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     IMDSCredentialRequest
		wantErr bool
	}{
		{
			name:    "valid",
			req:     IMDSCredentialRequest{CSR: "csr", AttestationToken: "tok"},
			wantErr: false,
		},
		{
			name:    "missing csr",
			req:     IMDSCredentialRequest{AttestationToken: "tok"},
			wantErr: true,
		},
		{
			name:    "missing attestation_token",
			req:     IMDSCredentialRequest{CSR: "csr"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// IMDSCredentialResponse tests
// ---------------------------------------------------------------------------

func TestIMDSCredentialResponse_Validate(t *testing.T) {
	valid := IMDSCredentialResponse{
		Certificate:                "cert",
		MtlsAuthenticationEndpoint: "https://mtls.example.com",
		TenantID:                   "tid",
		ClientID:                   "cid",
	}
	if err := valid.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}

	for _, field := range []string{"certificate", "mtls", "tenantId", "clientId"} {
		r := valid
		switch field {
		case "certificate":
			r.Certificate = ""
		case "mtls":
			r.MtlsAuthenticationEndpoint = ""
		case "tenantId":
			r.TenantID = ""
		case "clientId":
			r.ClientID = ""
		}
		if err := r.Validate(); err == nil {
			t.Errorf("expected error when %s is empty", field)
		}
	}
}

func TestIMDSCredentialResponse_ResolveTokenEndpoint(t *testing.T) {
	t.Run("explicit TokenEndpoint", func(t *testing.T) {
		r := IMDSCredentialResponse{
			Certificate:                "cert",
			MtlsAuthenticationEndpoint: "https://mtls.example.com",
			TokenEndpoint:              "https://explicit.token.endpoint",
			TenantID:                   "tid",
			ClientID:                   "cid",
		}
		ep, err := r.ResolveTokenEndpoint()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ep != "https://explicit.token.endpoint" {
			t.Errorf("endpoint = %q, want %q", ep, "https://explicit.token.endpoint")
		}
	})

	t.Run("derived from MtlsAuthenticationEndpoint", func(t *testing.T) {
		r := IMDSCredentialResponse{
			Certificate:                "cert",
			MtlsAuthenticationEndpoint: "https://mtls.example.com",
			TenantID:                   "tid",
			ClientID:                   "cid",
		}
		ep, err := r.ResolveTokenEndpoint()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "https://mtls.example.com/tid/oauth2/v2.0/token"
		if ep != want {
			t.Errorf("endpoint = %q, want %q", ep, want)
		}
	})

	t.Run("trailing slash trimmed", func(t *testing.T) {
		r := IMDSCredentialResponse{
			Certificate:                "cert",
			MtlsAuthenticationEndpoint: "https://mtls.example.com/",
			TenantID:                   "tid",
			ClientID:                   "cid",
		}
		ep, err := r.ResolveTokenEndpoint()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "https://mtls.example.com/tid/oauth2/v2.0/token"
		if ep != want {
			t.Errorf("endpoint = %q, want %q", ep, want)
		}
	})
}

func TestIMDSCredentialResponse_JSONRoundTrip(t *testing.T) {
	raw := `{"certificate":"cert","mtls_authentication_endpoint":"https://mtls.example.com","token_endpoint":"https://tok.ep","tenant_id":"tid","client_id":"cid"}`
	var resp IMDSCredentialResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if resp.Certificate != "cert" {
		t.Errorf("Certificate = %q, want %q", resp.Certificate, "cert")
	}
	if resp.TokenEndpoint != "https://tok.ep" {
		t.Errorf("TokenEndpoint = %q, want %q", resp.TokenEndpoint, "https://tok.ep")
	}
}

// ---------------------------------------------------------------------------
// EstsTokenRequest tests
// ---------------------------------------------------------------------------

func TestEstsTokenRequest_Validate(t *testing.T) {
	valid := EstsTokenRequest{
		GrantType: "client_credentials",
		ClientID:  "cid",
		Scope:     "https://resource/.default",
		TokenType: "mtls_pop",
	}
	if err := valid.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}

	empty := EstsTokenRequest{}
	if err := empty.Validate(); err == nil {
		t.Error("expected error for empty EstsTokenRequest")
	}
}

// ---------------------------------------------------------------------------
// EstsTokenResponse tests
// ---------------------------------------------------------------------------

func TestEstsTokenResponse_Validate(t *testing.T) {
	valid := EstsTokenResponse{AccessToken: "tok", TokenType: "mtls_pop", ExpiresIn: 3599}
	if err := valid.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
	if err := (&EstsTokenResponse{}).Validate(); err == nil {
		t.Error("expected error for empty EstsTokenResponse")
	}
}

func TestEstsTokenResponse_JSONRoundTrip(t *testing.T) {
	raw := `{"access_token":"tok","token_type":"mtls_pop","expires_in":3599}`
	var resp EstsTokenResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if resp.AccessToken != "tok" {
		t.Errorf("AccessToken = %q, want %q", resp.AccessToken, "tok")
	}
	if resp.ExpiresIn != 3599 {
		t.Errorf("ExpiresIn = %d, want 3599", resp.ExpiresIn)
	}
}

// ---------------------------------------------------------------------------
// TokenBinding / VerifyToken tests
// ---------------------------------------------------------------------------

// buildJWT creates a compact JWT with the given claims JSON in the payload.
// The signature segment is a placeholder; parseJWTClaims does not verify it.
func buildJWT(claimsJSON string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(claimsJSON))
	return header + "." + payload + ".sig"
}

func TestTokenBinding_Thumbprint(t *testing.T) {
	certDER := []byte("fake-der-bytes")
	sum := sha256.Sum256(certDER)
	want := base64.RawURLEncoding.EncodeToString(sum[:])

	tb := &TokenBinding{CertDER: certDER}
	got := tb.Thumbprint()
	if got != want {
		t.Errorf("Thumbprint() = %q, want %q", got, want)
	}
}

func TestTokenBinding_VerifyToken_Match(t *testing.T) {
	certDER := []byte("fake-der-bytes")
	sum := sha256.Sum256(certDER)
	thumbprint := base64.RawURLEncoding.EncodeToString(sum[:])

	claims := map[string]interface{}{
		"cnf": map[string]interface{}{"x5t#S256": thumbprint},
	}
	claimsJSON, _ := json.Marshal(claims)
	jwt := buildJWT(string(claimsJSON))

	tb := &TokenBinding{CertDER: certDER}
	if err := tb.VerifyToken(jwt); err != nil {
		t.Errorf("VerifyToken() unexpected error: %v", err)
	}
}

func TestTokenBinding_VerifyToken_Mismatch(t *testing.T) {
	certDER := []byte("fake-der-bytes")

	claims := map[string]interface{}{
		"cnf": map[string]interface{}{"x5t#S256": "wrong-thumbprint"},
	}
	claimsJSON, _ := json.Marshal(claims)
	jwt := buildJWT(string(claimsJSON))

	tb := &TokenBinding{CertDER: certDER}
	if err := tb.VerifyToken(jwt); err == nil {
		t.Error("VerifyToken() expected error for mismatched thumbprint, got nil")
	}
}

func TestTokenBinding_VerifyToken_InvalidJWT(t *testing.T) {
	tb := &TokenBinding{CertDER: []byte("cert")}
	tests := []struct {
		name  string
		token string
	}{
		{"one segment", "onlyonepart"},
		{"two segments", "header.payload"},
		{"five segments", "not.a.jwt.with.extra"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tb.VerifyToken(tt.token); err == nil {
				t.Errorf("VerifyToken(%q) expected error for malformed JWT, got nil", tt.token)
			}
		})
	}
}

func TestParseJWTClaims_MalformedPayload(t *testing.T) {
	// Payload segment is not valid base64url
	jwt := "header.!!!invalid!!!.sig"
	_, err := parseJWTClaims(jwt)
	if err == nil {
		t.Error("expected error for invalid base64url payload")
	}
}

func TestParseJWTClaims_InvalidJSON(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte("{not json}"))
	jwt := "header." + payload + ".sig"
	_, err := parseJWTClaims(jwt)
	if err == nil {
		t.Error("expected error for invalid JSON payload")
	}
}

// ---------------------------------------------------------------------------
// ResourceCallRequest tests
// ---------------------------------------------------------------------------

func TestResourceCallRequest_Validate(t *testing.T) {
	valid := ResourceCallRequest{
		ResourceURL: "https://resource.example.com",
		AccessToken: "tok",
		Certificate: []byte("cert"),
	}
	if err := valid.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}

	for _, field := range []string{"url", "token", "cert"} {
		r := valid
		switch field {
		case "url":
			r.ResourceURL = ""
		case "token":
			r.AccessToken = ""
		case "cert":
			r.Certificate = nil
		}
		if err := r.Validate(); err == nil {
			t.Errorf("expected error when %s is empty", field)
		}
	}
}

// ---------------------------------------------------------------------------
// Error model tests
// ---------------------------------------------------------------------------

func TestIMDSError_ErrorMessage(t *testing.T) {
	e := &IMDSError{StatusCode: 400, Error: "bad_request", ErrorDescription: "details"}
	msg := e.ErrorMessage()
	if !strings.Contains(msg, "400") || !strings.Contains(msg, "bad_request") {
		t.Errorf("ErrorMessage() = %q, expected status and code", msg)
	}
}

func TestMAAError_ErrorMessage(t *testing.T) {
	e := &MAAError{StatusCode: 401, Error: "unauthorized", ErrorDescription: "details"}
	msg := e.ErrorMessage()
	if !strings.Contains(msg, "401") || !strings.Contains(msg, "unauthorized") {
		t.Errorf("ErrorMessage() = %q, expected status and code", msg)
	}
}

func TestEstsError_ErrorMessage(t *testing.T) {
	e := &EstsError{StatusCode: 403, Error: "forbidden", ErrorDescription: "details", CorrelationID: "corr-123"}
	msg := e.ErrorMessage()
	if !strings.Contains(msg, "403") || !strings.Contains(msg, "forbidden") || !strings.Contains(msg, "corr-123") {
		t.Errorf("ErrorMessage() = %q, expected status, code and correlationId", msg)
	}
}
