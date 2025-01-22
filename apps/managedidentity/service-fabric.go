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
	if len(rawCerts) > 0 {
		cert := rawCerts[0]
		parsedCert, err := x509.ParseCertificate(cert)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}
		expectedThumbprint := os.Getenv(identityServerThumbprintEnvVar)
		if expectedThumbprint == "" {
			return fmt.Errorf("identity server thumbprint is not set in environment variables")
		}
		certThumbprint := getCertThumbprint(parsedCert)
		if certThumbprint != expectedThumbprint {
			return fmt.Errorf("certificate thumbprint does not match the expected value")
		}
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
