// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	// AccessTokenTypeMtlsPop is the token type for mTLS Proof of Possession tokens (RFC 8705).
	AccessTokenTypeMtlsPop = "mtls_pop"

	// mtlsAuthPublicCloud is the mTLS authentication host suffix for public Azure cloud.
	mtlsAuthPublicCloud = "mtlsauth.microsoft.com"

	// mtlsAuthUSGov is the mTLS authentication host suffix for Azure US Government cloud.
	mtlsAuthUSGov = "mtlsauth.microsoftonline.us"

	// mtlsAuthChina is the mTLS authentication host suffix for Azure China cloud.
	mtlsAuthChina = "mtlsauth.partner.microsoftonline.cn"
)

// MtlsPopAuthenticationScheme implements AuthenticationScheme for mTLS Proof of Possession tokens.
// It satisfies RFC 8705 by binding the access token to the client certificate presented in the TLS
// handshake. No client_assertion JWT is sent; the cert authenticates via the TLS handshake itself.
// This mirrors MSAL.NET's MtlsPopAuthenticationOperation.
type MtlsPopAuthenticationScheme struct {
	// Cert is the X.509 certificate used for mTLS binding. Set on the AuthResult.BindingCertificate.
	Cert *x509.Certificate
	// keyID is the pre-computed x5t#S256 thumbprint (SHA-256 of cert.Raw, Base64URL-encoded without padding).
	keyID string
}

// NewMtlsPopAuthenticationScheme creates a MtlsPopAuthenticationScheme for the given certificate.
// The cert's x5t#S256 thumbprint is computed once on construction and used as the cache key.
func NewMtlsPopAuthenticationScheme(cert *x509.Certificate) *MtlsPopAuthenticationScheme {
	hash := sha256.Sum256(cert.Raw)
	return &MtlsPopAuthenticationScheme{
		Cert:  cert,
		keyID: base64.RawURLEncoding.EncodeToString(hash[:]),
	}
}

// TokenRequestParams returns {"token_type": "mtls_pop"} to request a bound token.
// No client_assertion is sent; authentication is via the TLS handshake.
func (s *MtlsPopAuthenticationScheme) TokenRequestParams() map[string]string {
	return map[string]string{
		"token_type": AccessTokenTypeMtlsPop,
	}
}

// KeyID returns the x5t#S256 thumbprint of the binding certificate, used as the cache key discriminator.
// This is SHA-256 of the certificate's DER-encoded bytes, Base64URL-encoded without padding.
// Mirrors MSAL.NET's CoreHelpers.ComputeX5tS256KeyId().
func (s *MtlsPopAuthenticationScheme) KeyID() string {
	return s.keyID
}

// FormatAccessToken returns the token as-is. The caller uses it as "Authorization: mtls_pop <token>".
func (s *MtlsPopAuthenticationScheme) FormatAccessToken(accessToken string) (string, error) {
	return accessToken, nil
}

// AccessTokenType returns "mtls_pop".
func (s *MtlsPopAuthenticationScheme) AccessTokenType() string {
	return AccessTokenTypeMtlsPop
}

// BuildMtlsEndpoint builds the mTLS token endpoint URL for the given region, tenant ID, and authority info.
// For DSTS authorities, no region is required and the standard DSTS token endpoint is used.
// For AAD authorities, the endpoint is https://{region}.mtlsauth.{cloud}/{tenantID}/oauth2/v2.0/token.
// This mirrors MSAL.NET's RegionAndMtlsDiscoveryProvider.
func BuildMtlsEndpoint(region, tenantID string, info Info) (string, error) {
	if info.AuthorityType == DSTS {
		// DSTS does not use regional mTLS endpoints
		return fmt.Sprintf("https://%s/dstsv2/%s/oauth2/v2.0/token", info.Host, tenantID), nil
	}

	if region == "" {
		return "", errors.New("mTLS PoP requires an Azure region; use WithAzureRegion() or AutoDetectRegion()")
	}

	mtlsHost := buildMtlsHost(region, info.Host)
	return fmt.Sprintf("https://%s/%s/oauth2/v2.0/token", mtlsHost, tenantID), nil
}

// buildMtlsHost maps an authority host to its sovereign-cloud mTLS host equivalent.
func buildMtlsHost(region, authorityHost string) string {
	switch {
	case strings.HasSuffix(authorityHost, ".microsoftonline.us") ||
		strings.HasSuffix(authorityHost, ".usgovcloudapi.net"):
		return fmt.Sprintf("%s.%s", region, mtlsAuthUSGov)
	case strings.HasSuffix(authorityHost, ".partner.microsoftonline.cn") ||
		strings.HasSuffix(authorityHost, ".chinacloudapi.cn"):
		return fmt.Sprintf("%s.%s", region, mtlsAuthChina)
	default:
		// Public cloud and all other clouds
		return fmt.Sprintf("%s.%s", region, mtlsAuthPublicCloud)
	}
}

// ResolveRegion returns the effective region string, triggering auto-detection via Azure IMDS
// when region is the sentinel value "TryAutoDetect". Returns empty string if auto-detection fails.
func ResolveRegion(ctx context.Context, region string) string {
	if region == autoDetectRegion {
		return detectRegion(ctx)
	}
	return region
}
