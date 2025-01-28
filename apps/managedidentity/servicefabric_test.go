package managedidentity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Mock certificate type that embeds x509.Certificate
type MockCertificate struct {
	*x509.Certificate
	SignatureError error // A field to simulate signature verification failure
}

// Override CheckSignatureFrom to simulate a failure or success
func (m *MockCertificate) CheckSignatureFrom(cert *x509.Certificate) error {
	if m.SignatureError != nil {
		return m.SignatureError // Simulate an error if SignatureError is set
	}
	return nil // Otherwise, return nil (no error)
}

// GenerateMockCert generates a mock self-signed certificate for testing
func GenerateMockCert() ([]byte, string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}

	notBefore := time.Now().Add(-time.Hour * 1)
	notAfter := time.Now().Add(time.Hour * 6)

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Specify the signature algorithm explicitly (e.g., SHA-256 with RSA)
	// template.SignatureAlgorithm = x509.SHA256WithRSA
	// Create the certificate (self-signed)
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, "", err
	}
	// Parse the certificate back from the raw DER bytes
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, "", err
	}
	thumbprint := getCertThumbprint(cert)

	// Compute the thumbprint (SHA1 hash of the certificate)
	// thumbprint := getCertThumbprint(&x509.Certificate{Raw: derBytes})

	return derBytes, thumbprint, nil
}

// Test sslCertificateChecker for valid certificate chain
func TestSslCertificateChecker_ValidCertificate(t *testing.T) {
	// Generate mock certificate and thumbprint
	rawCert, expectedThumbprint, err := GenerateMockCert()
	if err != nil {
		t.Fatalf("Failed to generate mock certificate: %v", err)
	}

	// Check that the thumbprint is calculated correctly
	thumbprint := getCertThumbprint(&x509.Certificate{Raw: rawCert})
	if thumbprint != expectedThumbprint {
		t.Fatalf("Expected thumbprint to match, but got: %s", thumbprint)
	}
	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		t.Fatalf("Expected No error parsing certificate, but got: %v", err)
	}
	verifiedChain := [][]*x509.Certificate{
		{
			cert,
		},
	}

	err = sslCertificateChecker([][]byte{rawCert}, verifiedChain)
	if err != nil {
		t.Errorf("Expected no error for valid certificate chain, but got: %v", err)
	}
}

// Test sslCertificateChecker for thumbprint mismatch
func TestSslCertificateChecker_ThumbprintMismatch(t *testing.T) {
	invalidCert := []byte("invalid_cert_data") // Simulate an invalid certificate data
	rawCert, _, err := GenerateMockCert()
	if err != nil {
		t.Fatalf("Failed to generate mock certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		t.Fatalf("Expected No error parsing certificate, but got: %v", err)
	}
	verifiedChain := [][]*x509.Certificate{
		{
			cert,
		},
	}

	err = sslCertificateChecker([][]byte{invalidCert}, verifiedChain)
	if err == nil {
		t.Fatalf("Expected error due to thumbprint mismatch, but got none")
	} else if !containsString(err.Error(), "SSL policy error: thumbprint mismatch") {
		t.Errorf("Expected error 'SSL policy error: thumbprint mismatch', but got: %v", err)
	}
}

// Test sslCertificateChecker for missing certificate chain
func TestSslCertificateChecker_MissingChain(t *testing.T) {
	err := sslCertificateChecker(nil, nil)
	if err == nil {
		t.Fatalf("Expected error due to missing certificate chain, but got none")
	} else if !containsString(err.Error(), "SSL policy error: no valid certificate chain found") {
		t.Errorf("Expected error 'SSL policy error: no valid certificate chain found', but got: %v", err)
	}
}

// Test NewHTTPClientWithCustomCertValidation with a mock
func TestNewHTTPClientWithCustomCertValidation(t *testing.T) {
	client, err := NewHTTPClientWithCustomCertValidation()
	if err != nil {
		t.Fatalf("Expected no error creating HTTP client, but got: %v", err)
	}

	// Check that the client is configured with the custom transport
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Expected custom transport to be of type *http.Transport, but got: %T", client.Transport)
	}

	if transport.TLSClientConfig == nil {
		t.Fatalf("Expected TLS config to be set in transport, but it was nil")
	}

	// Optionally, you can mock VerifyPeerCertificate and test if it’s correctly set up.
	tlsConfig := transport.TLSClientConfig
	if tlsConfig.VerifyPeerCertificate == nil {
		t.Fatalf("Expected custom VerifyPeerCertificate function to be set, but it was nil")
	}
}

// Test sslCertificateChecker for failed signature verification
func TestSslCertificateChecker_FailedSignatureVerification(t *testing.T) {
	// Create a mock certificate with a simulated signature verification failure
	mockCert := &MockCertificate{
		Certificate:    &x509.Certificate{Raw: []byte("mock_cert_data")},
		SignatureError: errors.New("signature verification failed"),
	}

	verifiedChain := [][]*x509.Certificate{
		{
			&x509.Certificate{Raw: mockCert.Raw},
		},
	}

	err := sslCertificateChecker([][]byte{mockCert.Raw}, verifiedChain)
	if err == nil {
		t.Fatalf("Expected error due to signature verification failure, but got none")
	} else if !containsString(err.Error(), "SSL policy error: thumbprint mismatch") {
		t.Errorf("Expected error 'SSL policy error: thumbprint mismatch', but got: %v", err)
	}
}

// Helper function to check if a string contains a substring (alternative to assert.Contains)
func containsString(str, substr string) bool {
	return strings.Contains(str, substr)
}
