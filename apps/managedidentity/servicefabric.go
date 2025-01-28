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

func customVerifyCertificate(cert *x509.Certificate, verifiedChain [][]*x509.Certificate, customPool *x509.CertPool) error {
	// If no verified chain is provided, return an error
	if len(verifiedChain) == 0 || len(verifiedChain[0]) == 0 {
		return fmt.Errorf("SSL policy error: no valid certificate chain found")
	}

	// Verify the chain using the custom trust store (pool)
	opts := x509.VerifyOptions{
		Roots: customPool, // Use the custom cert pool
	}

	// Perform certificate verification based on the provided chain
	_, err := cert.Verify(opts)
	if err != nil {
		// Check if the error is an UnknownAuthorityError
		return fmt.Errorf("Certificate verification failed: %v", err)
	}

	// Verify the chain's integrity: the server cert must be signed by the intermediate certs, ending at the root
	for i := 0; i < len(verifiedChain)-1; i++ {
		// Get the issuer (parent cert) and the child cert (server cert or intermediate)
		issuerCert := verifiedChain[i][0]
		childCert := verifiedChain[i+1][0]

		// Check that the issuer can sign the child certificate
		if err := childCert.CheckSignatureFrom(issuerCert); err != nil {
			return fmt.Errorf("SSL policy error: certificate signature verification failed at level %d", i+1)
		}
	}

	// At this point, all certificates in the chain are verified
	return nil
}

// sslCertificateChecker verifies a certificate chain and checks for SSL policy errors
func sslCertificateChecker(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	// If there are SSL policy errors (in this case, we simulate it using a custom validation condition)
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		return fmt.Errorf("SSL policy error: no valid certificate chain found")
	}
	customPool := x509.NewCertPool()
	customPool.AddCert(verifiedChains[0][0])
	// Check the chain for validity, you can use the first chain as the main one
	serverCert := verifiedChains[0][0]

	// Custom thumbprint check
	thumbprint := getCertThumbprint(serverCert)
	expectedThumbprint := getCertThumbprintFromRawCert(rawCerts[0])

	if !strings.EqualFold(thumbprint, expectedThumbprint) {
		return fmt.Errorf("SSL policy error: thumbprint mismatch")
	}

	// Use the custom certificate verification method
	err := customVerifyCertificate(serverCert, verifiedChains, customPool)
	if err != nil {
		return fmt.Errorf("SSL policy error: certificate verification failed: %v", err)
	}

	return nil
}

func getCertThumbprintFromRawCert(rawCert []byte) string {
	// Parse the raw certificate to get the x509.Certificate
	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		// Return an error thumbprint in case of invalid certificate
		fmt.Printf("Failed to parse certificate: %v\n", err)
		return ""
	}

	// Calculate the thumbprint of the parsed certificate
	return getCertThumbprint(cert)
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
		InsecureSkipVerify:    true,
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
