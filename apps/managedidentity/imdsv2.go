// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/google/uuid"
)

const (
	imdsV2PlatformMetadataEndpoint = "http://169.254.169.254/metadata/identity/getplatformmetadata"
	imdsV2IssueCredentialEndpoint  = "http://169.254.169.254/metadata/identity/issuecredential?cred-api-version=2.0"
	imdsV2CredAPIVersion           = "2.0"
)

type csrMetadata struct {
	ClientID            string         `json:"clientId"`
	TenantID            string         `json:"tenantId"`
	NotBefore           string         `json:"notBefore,omitempty"`
	RequestID           string         `json:"requestId,omitempty"`
	CuID                csrMetadataCuID `json:"cuId,omitempty"`
	AttestationEndpoint string         `json:"attestationEndpoint,omitempty"`
}

// csrMetadataCuID represents the cuId object in the IMDS platform metadata response.
// Mirrors MSAL.NET's CuidInfo: {"vmId":"...", "vmssId":"..."}.
type csrMetadataCuID struct {
	VmID   string `json:"vmId,omitempty"`
	VmssID string `json:"vmssId,omitempty"`
}

// cuIDString returns the VM ID from the cuId object, or an empty string if not set.
func (c csrMetadataCuID) cuIDString() string {
	return c.VmID
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
	req.Header.Set("x-ms-client-request-id", uuid.New().String())

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
	httpReq.Header.Set("x-ms-client-request-id", uuid.New().String())

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
// generateCSR creates a PKCS#10 CSR that exactly matches MSAL.NET's Csr.Generate():
//
//   - Subject:   CN={clientId}, DC={tenantId}
//   - Public key: RSA (from the provided signer)
//   - Attribute:  OID 1.3.6.1.4.1.311.90.2.10 = ASN.1 UTF8String of JSON-serialized cuID
//   - Signature:  RSASSA-PSS with SHA-256 (salt length = hash length = 32)
//
// Returns base64-encoded DER (no PEM headers), matching csrPem after header stripping.
func generateCSR(key crypto.Signer, clientID, tenantID string, cuID csrMetadataCuID) (string, error) {
	// --- Subject: CN={clientId}, DC={tenantId} ---
	// OID for domainComponent: 0.9.2342.19200300.100.1.25
	dcOID := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	subject := pkix.Name{
		CommonName: clientID,
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: dcOID, Value: tenantID},
		},
	}
	subjectDER, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		return "", fmt.Errorf("marshal subject: %w", err)
	}

	// --- SubjectPublicKeyInfo ---
	pubKeyDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	var spki asn1.RawValue
	if _, err := asn1.Unmarshal(pubKeyDER, &spki); err != nil {
		return "", fmt.Errorf("unmarshal spki: %w", err)
	}

	// --- CuID attribute: OID 1.3.6.1.4.1.311.90.2.10, value = SET { UTF8String(json) } ---
	cuIDJSON, err := json.Marshal(cuID)
	if err != nil {
		return "", fmt.Errorf("marshal cuID: %w", err)
	}
	// Encode as ASN.1 UTF8String (tag 0x0C)
	utf8Bytes, err := asn1.MarshalWithParams(string(cuIDJSON), "utf8")
	if err != nil {
		return "", fmt.Errorf("marshal utf8 cuID: %w", err)
	}
	// Wrap in SET OF
	cuIDValueSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      utf8Bytes,
	})
	if err != nil {
		return "", fmt.Errorf("marshal cuID value set: %w", err)
	}
	// Build attribute SEQUENCE { OID, SET }
	cuIDOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 90, 2, 10}
	oidBytes, err := asn1.Marshal(cuIDOID)
	if err != nil {
		return "", fmt.Errorf("marshal cuID OID: %w", err)
	}
	cuIDAttr, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      append(oidBytes, cuIDValueSet...),
	})
	if err != nil {
		return "", fmt.Errorf("marshal cuID attr: %w", err)
	}
	// attributes [0] IMPLICIT SET OF { cuIDAttr }
	attributes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      cuIDAttr,
	})
	if err != nil {
		return "", fmt.Errorf("marshal attributes: %w", err)
	}

	// --- CertificationRequestInfo SEQUENCE { version, subject, spki, attributes } ---
	version, err := asn1.Marshal(0)
	if err != nil {
		return "", fmt.Errorf("marshal version: %w", err)
	}
	// Guard against integer overflow in the capacity calculation (CodeQL).
	totalLen := len(version)
	if totalLen > math.MaxInt-len(subjectDER) {
		return "", fmt.Errorf("certification request info too large")
	}
	totalLen += len(subjectDER)
	if totalLen > math.MaxInt-len(pubKeyDER) {
		return "", fmt.Errorf("certification request info too large")
	}
	totalLen += len(pubKeyDER)
	if totalLen > math.MaxInt-len(attributes) {
		return "", fmt.Errorf("certification request info too large")
	}
	totalLen += len(attributes)
	certReqInfoBytes := make([]byte, 0, totalLen)
	certReqInfoBytes = append(certReqInfoBytes, version...)
	certReqInfoBytes = append(certReqInfoBytes, subjectDER...)
	certReqInfoBytes = append(certReqInfoBytes, spki.FullBytes...)
	certReqInfoBytes = append(certReqInfoBytes, attributes...)
	certReqInfo, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certReqInfoBytes,
	})
	if err != nil {
		return "", fmt.Errorf("marshal certReqInfo: %w", err)
	}

	// --- Sign with RSASSA-PSS SHA-256 (salt = hash length = 32) ---
	h := crypto.SHA256.New()
	h.Write(certReqInfo)
	digest := h.Sum(nil)
	sig, err := key.Sign(rand.Reader, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return "", fmt.Errorf("signing CSR: %w", err)
	}

	// --- RSASSA-PSS AlgorithmIdentifier (OID 1.2.840.113549.1.1.10 with SHA-256 params) ---
	// SEQUENCE { OID sha-256 } for hash algo and MGF
	sha256AlgID, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes: func() []byte {
			b, _ := asn1.Marshal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}) // id-sha256
			n, _ := asn1.Marshal(asn1.NullRawValue)
			return append(b, n...)
		}(),
	})
	mgfAlgID, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes: func() []byte {
			b, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}) // id-mgf1
			return append(b, sha256AlgID...)
		}(),
	})
	saltLen, _ := asn1.Marshal(32) // SHA-256 output = 32 bytes
	pssParamsBytes := append(
		tagExplicit(0, sha256AlgID),
		append(tagExplicit(1, mgfAlgID), tagExplicit(2, saltLen)...)...,
	)
	pssParams, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      pssParamsBytes,
	})
	pssOID, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}) // id-RSASSA-PSS
	sigAlgID, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      append(pssOID, pssParams...),
	})

	// --- Final CertificationRequest SEQUENCE { certReqInfo, sigAlgID, signature BIT STRING } ---
	sigBitString, _ := asn1.Marshal(asn1.BitString{Bytes: sig, BitLength: len(sig) * 8})
	csrBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      append(certReqInfo, append(sigAlgID, sigBitString...)...),
	})
	if err != nil {
		return "", fmt.Errorf("marshal CSR: %w", err)
	}
	return base64.StdEncoding.EncodeToString(csrBytes), nil
}

// tagExplicit wraps bytes in a context-specific explicit tag [N].
func tagExplicit(n int, content []byte) []byte {
	b, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        n,
		IsCompound: true,
		Bytes:      content,
	})
	return b
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
		// a. Get/create CNG key — mirrors MSAL.NET WindowsManagedIdentityKeyProvider:
		//    Priority: KeyGuard (VBS) > Hardware (Software KSP) > InMemory (ephemeral RSA)
		cuID := meta.CuID.cuIDString()
		if cuID == "" {
			cuID = meta.ClientID
		}
		key, keyType, err := GetOrCreateManagedIdentityKey("MSALMtlsKey_" + cuID)
		if err != nil {
			return nil, fmt.Errorf("GetOrCreateManagedIdentityKey: %w", err)
		}

		// mTLS PoP requires a VBS KeyGuard-protected key. Hardware and InMemory keys
		// are not accepted. This matches MSAL.NET's "mtls_pop_requires_keyguard" check.
		if keyType != keyTypeKeyGuard {
			return nil, fmt.Errorf(
				"mTLS PoP requires a VBS KeyGuard-protected RSA key (got: %s). "+
					"Ensure Credential Guard / Core Isolation is enabled on this VM: "+
					"Trusted Launch (Secure Boot + vTPM) must be enabled, and VBS/Credential Guard "+
					"must be active (check msinfo32.exe: 'Virtualization-based security' = Running). "+
					"See docs/mtls-pop-manual-testing.md for VM setup instructions.",
				keyType)
		}

		// b. Generate CSR
		csrB64, err := generateCSR(key, meta.ClientID, meta.TenantID, meta.CuID)
		if err != nil {
			return nil, fmt.Errorf("generateCSR: %w", err)
		}

		// c. Get MAA JWT attestation: proves to IMDS that the key is hardware-protected
		// (KeyGuard/VBS). Only called for KeyGuard keys — mirrors MSAL.NET which only
		// attests when keyInfo.Type == ManagedIdentityKeyType.KeyGuard.
		var attestationToken string
		if keyType == keyTypeKeyGuard && meta.AttestationEndpoint != "" {
			attestationToken, err = GetKeyGuardAttestationJWT(key, meta.AttestationEndpoint, meta.ClientID)
			if err != nil {
				return nil, fmt.Errorf("GetKeyGuardAttestationJWT: %w", err)
			}
		}

		// d. Issue credential
		credResp, err := issueCredential(ctx, c.httpClient, issueCredentialRequest{
			CSR:              csrB64,
			AttestationToken: attestationToken,
		})
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

	// 3. Check token cache before making a network request
	mtlsScheme := authority.NewMtlsPopAuthenticationScheme(info.x509Cert)
	cacheAuthParams := c.authParams
	cacheAuthParams.Scopes = []string{resource}
	cacheAuthParams.AuthnScheme = mtlsScheme
	if stResp, cacheErr := cacheManager.Read(ctx, cacheAuthParams); cacheErr == nil {
		if ar, arErr := base.AuthResultFromStorage(stResp); arErr == nil {
			ar.BindingCertificate = info.x509Cert
			ar.AccessToken, _ = mtlsScheme.FormatAccessToken(ar.AccessToken)
			return ar, nil
		}
	}

	// 4. Build token endpoint
	tokenEndpoint := info.endpoint
	if !strings.HasSuffix(tokenEndpoint, "/") {
		tokenEndpoint += "/"
	}
	tokenEndpoint += info.tenantID + "/oauth2/v2.0/token"

	// 5. Build mTLS HTTP client
	mtlsHTTPClient := newMtlsHTTPClient(info.tlsCert)

	// 6. POST token request
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

	// Build authParams with the mTLS PoP scheme for cache key discrimination
	authParams := c.authParams
	authParams.Scopes = []string{resource}
	authParams.AuthnScheme = mtlsScheme

	// 7. Write to cache and build AuthResult
	account, err := cacheManager.Write(authParams, tokenResp)
	if err != nil {
		return AuthResult{}, fmt.Errorf("writing token to cache: %w", err)
	}
	ar, err := base.NewAuthResult(tokenResp, account)
	if err != nil {
		return AuthResult{}, err
	}
	ar.AccessToken, err = mtlsScheme.FormatAccessToken(ar.AccessToken)
	return ar, err
}
