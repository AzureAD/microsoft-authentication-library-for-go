package managedidentity

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem" // Import for pemEncodeCert
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"

	// "os"
	"time"
)

const (
	searchSubject   = "CN=devicecert.mtlsauth.local"                                             // Existing cert to look for (PowerShell: $searchSubject)
	newCertSubject  = "CN=mtls-auth"                                                             // Subject for new self-signed cert (PowerShell: $newCertSubject)
	certStorePath   = "/tmp/certs"                                                               // Example path for storing self-signed cert on Linux (adjust as needed)
	certFileName    = "mtls-auth.pem"                                                            // Filename for the self-signed cert
	imdsEndpoint    = "http://169.254.169.254/metadata/identity/credential?cred-api-version=1.0" // IMDS Endpoint
	managementScope = "https://management.azure.com/.default"                                    // Management Scope for Azure Token
)

// Define JWK struct for JSON payload
type JWK struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Alg string   `json:"alg"`
	Kid string   `json:"kid"`
	X5c []string `json:"x5c"`
}

// Define CNF struct for JSON payload
type CNF struct {
	JWK JWK `json:"jwk"`
}

// Define RequestBody struct for JSON payload
type RequestBody struct {
	CNF      CNF  `json:"cnf"`
	LatchKey bool `json:"latch_key"`
}

// IMDSResponse struct to unmarshal IMDS response
type IMDSResponse struct {
	RegionalTokenURL string `json:"regional_token_url"`
	TenantID         string `json:"tenant_id"`
	ClientID         string `json:"client_id"`
	Credential       string `json:"credential"`
}

// AzureTokenResponse struct to unmarshal Azure token response
type AzureTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	ExtExpiresIn int    `json:"ext_expires_in"`
}

func main() {
	var cert *x509.Certificate
	var err error
	var tempKey *rsa.PrivateKey
	// Step 1 & 2: Search for an existing certificate (Simplified for Linux - Implement actual search if needed)
	// In Linux, certificate management is different from Windows.
	// This example skips searching and directly creates a new cert for simplicity.
	// For real-world Linux scenarios, you might need to integrate with system certificate stores
	// or use specific paths to search for certificates.
	fmt.Println("🔍 Searching for existing certificate... (Skipped in this example for Linux)")
	cert = nil // In a real implementation, search logic would be here and assign to 'cert' if found.

	// Step 3: If found, use it, else create a new self-signed cert
	if cert != nil {
		fmt.Printf("✅ Found valid certificate: %s\n", cert.Subject.String()) // If certificate search was implemented
	} else {
		fmt.Println("❌ No valid certificate found. Creating a new self-signed certificate...")
		cert, tempKey, err = createSelfSignedCertificate()
		if err != nil {
			log.Fatalf("❌ Failed to create self-signed certificate: %v", err)
		}
		fmt.Printf("✅ Created certificate: %s\n", cert.Subject.String())
	}

	// Ensure cert is valid (already checked in createSelfSignedCertificate, but double check in a real search scenario)
	if cert == nil {
		log.Fatal("❌ No certificate found or created. Exiting.")
	}

	// Step 5: Compute SHA-256 of the Public Key for kid
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		log.Fatalf("❌ Failed to marshal public key: %v", err)
	}
	sha256Hash := sha256.Sum256(publicKeyBytes)
	certSha256 := hex.EncodeToString(sha256Hash[:])
	fmt.Printf("🔐 Using SHA-256 Certificate Identifier (kid): %s\n", certSha256)

	// Step 6: Convert certificate to Base64 for JWT (x5c field)
	x5c := base64.StdEncoding.EncodeToString(cert.Raw)
	fmt.Printf("📜 x5c: %s\n", x5c)

	// Step 7: Construct the JSON body
	bodyObject := RequestBody{
		CNF: CNF{
			JWK: JWK{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: certSha256,
				X5c: []string{x5c}, // Ensure correct array formatting
			},
		},
		LatchKey: false, // Final version should not have this.
	}

	bodyBytes, err := json.Marshal(bodyObject)
	if err != nil {
		log.Fatalf("❌ Failed to marshal JSON body: %v", err)
	}
	body := string(bodyBytes)
	fmt.Printf("🔹 JSON Payload: %s\n", body)

	// Step 8: Request MSI credential
	headers := map[string][]string{
		"Metadata":               {"true"},
		"X-ms-Client-Request-id": {generateGUID()},
		"Content-Type":           {"application/json"}, // Important: Set Content-Type to application/json
	}

	imdsResponse, err := makeHTTPRequest("POST", imdsEndpoint, headers, bytes.NewBuffer(bodyBytes))
	if err != nil {
		log.Fatalf("❌ Failed to request MSI credential: %v", err)
	}

	var jsonContent IMDSResponse
	err = json.Unmarshal(imdsResponse, &jsonContent)
	if err != nil {
		log.Fatalf("❌ Failed to unmarshal IMDS response: %v", err)
	}

	regionalEndpoint := jsonContent.RegionalTokenURL + "/" + jsonContent.TenantID + "/oauth2/v2.0/token"
	fmt.Printf("✅ Using Regional Endpoint: %s\n", regionalEndpoint)
	println(regionalEndpoint)
	// Step 9: Authenticate with Azure
	tokenHeaders := map[string][]string{
		"Content-Type": {"application/x-www-form-urlencoded"},
		"Accept":       {"application/json"},
	}

	tokenRequestBody := url.Values{}
	tokenRequestBody.Set("grant_type", "client_credentials")
	tokenRequestBody.Set("scope", managementScope)
	tokenRequestBody.Set("client_id", jsonContent.ClientID)
	tokenRequestBody.Set("client_assertion", jsonContent.Credential)
	tokenRequestBody.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")

	tokenResponse, err := makeHTTPRequestCert("POST", regionalEndpoint, tokenHeaders, bytes.NewBufferString(tokenRequestBody.Encode()), cert, tempKey)
	if err != nil {
		log.Fatalf("❌ Failed to retrieve access token: %v", err)
	}

	var tokenJson AzureTokenResponse
	err = json.Unmarshal(tokenResponse, &tokenJson)
	if err != nil {
		log.Fatalf("❌ Failed to unmarshal token response: %v", err)
	}

	fmt.Printf("🔑 Access Token:  %s\n", tokenJson.AccessToken)
	fmt.Printf("🔑 Access Token: %s\n", tokenJson.ExpiresIn)
	fmt.Printf("🔑 Access Token: %s\n", tokenJson.TokenType)

}

// createSelfSignedCertificate generates a self-signed certificate
func createSelfSignedCertificate() (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Serial Number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Validity period
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 90) // 90 days

	// Subject
	subject := pkix.Name{
		CommonName: newCertSubject, // Assuming newCertSubject is defined globally
	}

	// Certificate Template
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Add Text Extension for Extended Key Usage (OID 1.3.6.1.5.5.7.3.2 - id-kp-clientAuth)
	oidEKUClientAuth := []int{1, 3, 6, 1, 5, 5, 7, 3, 2} // id-kp-clientAuth
	template.UnknownExtKeyUsage = append(template.UnknownExtKeyUsage, oidEKUClientAuth)

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, privateKey, nil
}

// makeHTTPRequest makes a HTTP request and returns the response body
func makeHTTPRequest(method, url string, headers map[string][]string, body io.Reader) ([]byte, error) {
	client := &http.Client{}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP error: %s, Body: %s", resp.Status, string(respBody))
	}

	return respBody, nil
}

// makeHTTPRequest makes a HTTP request and returns the response body
func makeHTTPRequestCert(method, url string, headers map[string][]string, body io.Reader, cert *x509.Certificate, key *rsa.PrivateKey) ([]byte, error) {

	// --- Create TLS Config with Client Certificate ---
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw}, // Raw DER-encoded certificate
		PrivateKey:  key,                // Private key
		Leaf:        cert,               // *x509.Certificate (important to include the parsed cert)
	}

	// // --- Create HTTP Client with TLS Config ---
	// transport := &http.Transport{
	// 	TLSClientConfig: tlsConfig,
	// }
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		log.Fatalf("❌ Failed to marshal public key: %v", err)
	}
	sha256Hash := sha256.Sum256(publicKeyBytes)
	certSha256 := hex.EncodeToString(sha256Hash[:])
	fmt.Printf("🔐 Generated Certificate SHA-256 (kid): %s\n", certSha256)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert}, // Use the in-memory tlsCert
	}

	// --- 5. Create HTTP Client with TLS Config ---
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{Transport: transport}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP error: %s, Body: %s", resp.Status, string(respBody))
	}

	return respBody, nil
}

// generateGUID generates a GUID string
func generateGUID() string {
	guid := make([]byte, 16)
	if _, err := rand.Read(guid); err != nil {
		return "error-generating-guid" // Fallback in case of error
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		guid[0:4], guid[4:6], guid[6:8], guid[8:10], guid[10:])
}

// pemEncodeCert encodes certificate to PEM format
func pemEncodeCert(w io.Writer, cert *x509.Certificate) error {
	if err := pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return err
	}
	return nil
}
