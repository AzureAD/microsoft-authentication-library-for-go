// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

const (
	imdsV2PlatformMetadataEndpoint = "http://169.254.169.254/metadata/identity/getplatformmetadata"
	imdsV2IssueCredentialEndpoint  = "http://169.254.169.254/metadata/identity/issuecredential"
	imdsV2CredAPIVersion           = "2.0"
)

type csrMetadata struct {
	ClientID            string `json:"client_id"`
	TenantID            string `json:"tenant_id"`
	NotBefore           string `json:"not_before,omitempty"`
	RequestID           string `json:"request_id,omitempty"`
	CuID                string `json:"cu_id,omitempty"`
	AttestationEndpoint string `json:"attestation_endpoint,omitempty"`
}

type credentialResponse struct {
	Certificate                string `json:"certificate"`
	MtlsAuthenticationEndpoint string `json:"mtls_authentication_endpoint"`
	ClientID                   string `json:"client_id"`
	TenantID                   string `json:"tenant_id"`
	RegionalTokenURL           string `json:"regional_token_url,omitempty"`
}

type issueCredentialRequest struct {
	CSR              string `json:"csr"`
	AttestationToken string `json:"attestation_token,omitempty"`
}

// getPlatformMetadata calls IMDS /getplatformmetadata to get the CSR metadata.
func getPlatformMetadata(ctx context.Context, httpClient ops.HTTPClient) (csrMetadata, error) {
	u := imdsV2PlatformMetadataEndpoint + "?cred-api-version=" + imdsV2CredAPIVersion
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return csrMetadata{}, fmt.Errorf("creating platform metadata request: %w", err)
	}
	req.Header.Set("Metadata", "true")

	resp, err := httpClient.Do(req)
	if err != nil {
		return csrMetadata{}, fmt.Errorf("getting platform metadata: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return csrMetadata{}, fmt.Errorf("reading platform metadata response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return csrMetadata{}, fmt.Errorf("platform metadata returned status %d: %s", resp.StatusCode, string(body))
	}

	var meta csrMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return csrMetadata{}, fmt.Errorf("parsing platform metadata: %w", err)
	}
	return meta, nil
}

// issueCredential submits a CSR to IMDS /issuecredential and returns the signed certificate.
func issueCredential(ctx context.Context, httpClient ops.HTTPClient, req issueCredentialRequest) (credentialResponse, error) {
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return credentialResponse{}, fmt.Errorf("marshaling issue credential request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, imdsV2IssueCredentialEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return credentialResponse{}, fmt.Errorf("creating issue credential request: %w", err)
	}
	httpReq.Header.Set("Metadata", "true")
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return credentialResponse{}, fmt.Errorf("issuing credential: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return credentialResponse{}, fmt.Errorf("reading issue credential response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return credentialResponse{}, fmt.Errorf("issue credential returned status %d: %s", resp.StatusCode, string(body))
	}

	var credResp credentialResponse
	if err := json.Unmarshal(body, &credResp); err != nil {
		return credentialResponse{}, fmt.Errorf("parsing issue credential response: %w", err)
	}
	return credResp, nil
}

// generateCSR generates a PKCS#10 CSR signed with the given key.
// The subject is CN=<clientID> and the CSR is returned as standard base64-encoded DER (no PEM headers).
func generateCSR(key crypto.Signer, clientID string) (string, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: clientID,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return "", fmt.Errorf("creating certificate request: %w", err)
	}
	return base64.StdEncoding.EncodeToString(csrDER), nil
}

// newMtlsHTTPClient creates an *http.Client configured for mutual TLS using the provided certificate.
func newMtlsHTTPClient(cert tls.Certificate) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		},
	}
}

// acquireTokenForImdsV2 acquires an mTLS PoP token using IMDSv2.
func (c Client) acquireTokenForImdsV2(ctx context.Context, resource string) (AuthResult, error) {
	if runtime.GOOS != "windows" {
		return AuthResult{}, errMtlsPopWindowsOnly
	}

	// 1. Get platform metadata
	meta, err := getPlatformMetadata(ctx, c.httpClient)
	if err != nil {
		return AuthResult{}, fmt.Errorf("IMDSv2 platform metadata: %w", err)
	}
	if meta.ClientID == "" || meta.TenantID == "" {
		return AuthResult{}, fmt.Errorf("IMDSv2 platform metadata missing client_id or tenant_id")
	}

	// 2. Get or create binding cert (with caching)
	cacheKey := meta.ClientID + "_" + meta.TenantID
	info, err := globalMtlsCertCache.GetOrCreate(ctx, cacheKey, func(ctx context.Context) (*mtlsBindingInfo, error) {
		// a. Get/create CNG key
		cuID := meta.CuID
		if cuID == "" {
			cuID = meta.ClientID
		}
		key, err := GetOrCreateKeyGuardKey("MSALMtlsKey_" + cuID)
		if err != nil {
			return nil, fmt.Errorf("GetOrCreateKeyGuardKey: %w", err)
		}

		// b. Generate CSR
		csrB64, err := generateCSR(key, meta.ClientID)
		if err != nil {
			return nil, fmt.Errorf("generateCSR: %w", err)
		}

		// c. Issue credential
		credResp, err := issueCredential(ctx, c.httpClient, issueCredentialRequest{CSR: csrB64})
		if err != nil {
			return nil, fmt.Errorf("issueCredential: %w", err)
		}

		// d. Parse cert DER from base64
		certDER, err := base64.StdEncoding.DecodeString(credResp.Certificate)
		if err != nil {
			return nil, fmt.Errorf("decoding certificate: %w", err)
		}
		x509Cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}

		clientID := credResp.ClientID
		if clientID == "" {
			clientID = meta.ClientID
		}
		tenantID := credResp.TenantID
		if tenantID == "" {
			tenantID = meta.TenantID
		}

		return &mtlsBindingInfo{
			tlsCert: tls.Certificate{
				Certificate: [][]byte{certDER},
				PrivateKey:  key,
				Leaf:        x509Cert,
			},
			x509Cert:  x509Cert,
			endpoint:  credResp.MtlsAuthenticationEndpoint,
			clientID:  clientID,
			tenantID:  tenantID,
			expiresAt: x509Cert.NotAfter.Add(-5 * time.Minute),
		}, nil
	})
	if err != nil {
		return AuthResult{}, fmt.Errorf("acquiring binding certificate: %w", err)
	}

	// 3. Build token endpoint
	tokenEndpoint := info.endpoint
	if !strings.HasSuffix(tokenEndpoint, "/") {
		tokenEndpoint += "/"
	}
	tokenEndpoint += info.tenantID + "/oauth2/v2.0/token"

	// 4. Build mTLS HTTP client
	mtlsHTTPClient := newMtlsHTTPClient(info.tlsCert)

	// 5. POST token request
	qv := url.Values{}
	qv.Set("grant_type", "client_credentials")
	qv.Set("client_id", info.clientID)
	qv.Set("scope", resource+"/.default")
	qv.Set("token_type", authority.AccessTokenTypeMtlsPop)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(qv.Encode()))
	if err != nil {
		return AuthResult{}, fmt.Errorf("creating token request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := mtlsHTTPClient.Do(httpReq)
	if err != nil {
		return AuthResult{}, fmt.Errorf("posting token request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return AuthResult{}, fmt.Errorf("reading token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return AuthResult{}, fmt.Errorf("token request returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp accesstokens.TokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return AuthResult{}, fmt.Errorf("parsing token response: %w", err)
	}
	tokenResp.GrantedScopes.Slice = append(tokenResp.GrantedScopes.Slice, resource)
	tokenResp.BindingCertificate = info.x509Cert

	// Build authParams for the mTLS endpoint, using the tenant from IMDS
	authParams := c.authParams
	authParams.Scopes = []string{resource}

	// 6. Write to cache and build AuthResult
	account, err := cacheManager.Write(authParams, tokenResp)
	if err != nil {
		return AuthResult{}, fmt.Errorf("writing token to cache: %w", err)
	}
	ar, err := base.NewAuthResult(tokenResp, account)
	if err != nil {
		return AuthResult{}, err
	}
	ar.AccessToken, err = authParams.AuthnScheme.FormatAccessToken(ar.AccessToken)
	return ar, err
}
