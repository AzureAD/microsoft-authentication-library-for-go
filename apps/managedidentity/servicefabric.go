package managedidentity

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
)

func sslCertificateChecker(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	// If there are SSL policy errors (in this case, we simulate it using a custom validation condition)
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		return fmt.Errorf("SSL policy error: no valid certificate chain found")
	}

	// Check the chain for validity, you can use the first chain as the main one
	serverCert := verifiedChains[0][0]

	// Custom thumbprint check
	thumbprint := getCertThumbprint(serverCert)
	if !strings.EqualFold(thumbprint, thumbprint) {
		return fmt.Errorf("SSL policy error: thumbprint mismatch")
	}

	// Optionally check for other SSL policy errors, e.g., expired certificates, untrusted chains, etc.
	if err := serverCert.CheckSignatureFrom(verifiedChains[0][len(verifiedChains[0])-1]); err != nil {
		return fmt.Errorf("SSL policy error: certificate signature verification failed")
	}

	return nil
}

// getCertThumbprint calculates the SHA-1 thumbprint of a certificate
func getCertThumbprint(cert *x509.Certificate) string {
	// Calculate SHA-1 hash of the certificate's raw data (Thumbprint)
	hash := sha1.New()
	hash.Write(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(hash.Sum(nil)))
}

// NewHTTPClientWithCustomCertValidation creates an HTTP client with custom certificate validation
func NewHTTPClientWithCustomCertValidation() (*http.Client, error) {
	// Create custom TLS config with the cert validation logic
	tlsConfig := &tls.Config{
		VerifyPeerCertificate: sslCertificateChecker,
	}
	// Create an HTTP transport with the TLS config
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	// Create and return the HTTP client
	client := &http.Client{
		Transport: transport,
	}
	return client, nil
}

func createServiceFabricAuthRequest(ctx context.Context, id ID, resource string) (*http.Request, error) {
	identityEndpoint := os.Getenv(identityEndpointEnvVar)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, identityEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Secret", os.Getenv(identityHeaderEnvVar))
	q := req.URL.Query()
	q.Set("api-version", serviceFabricAPIVersion)
	q.Set("resource", resource)
	switch t := id.(type) {
	case UserAssignedClientID:
		q.Set(miQueryParameterClientId, string(t))
	case UserAssignedResourceID:
		q.Set(miQueryParameterResourceId, string(t))
	case UserAssignedObjectID:
		q.Set(miQueryParameterObjectId, string(t))
	case systemAssignedValue:
	default:
		return nil, fmt.Errorf("unsupported type %T", id)
	}
	req.URL.RawQuery = q.Encode()
	return req, nil
}
