package msalbase

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/json"
	jwt "github.com/dgrijalva/jwt-go"
	uuid "github.com/google/uuid"
	"github.com/shirou/gopsutil/host"
)

type accessTokenProvider interface {
	GetSecret() string
	GetExpiresOn() string
	GetScopes() string
}

// ClientAssertion holds the assertion parameters required for token acquisition flows needing a client assertion.
// This can be either a JWT or certificate.
type ClientAssertion struct {
	ClientAssertionJWT string
	ClientCertificate  *ClientCertificate
}

// CreateClientAssertionFromJWT creates a ClientAssertion instance from a JWT.
func CreateClientAssertionFromJWT(jwt string) *ClientAssertion {
	return &ClientAssertion{ClientAssertionJWT: jwt, ClientCertificate: nil}
}

// CreateClientAssertionFromCertificate creates a ClientAssertion instance from a certificate (thumbprint and private key).
func CreateClientAssertionFromCertificate(thumbprint string, key []byte) *ClientAssertion {
	cert := CreateClientCertificate(thumbprint, key)
	assertion := &ClientAssertion{ClientCertificate: cert}
	return assertion
}

// CreateClientAssertionFromCertificateObject creates a ClientAssertion instance from a ClientCertificate Instance.
func CreateClientAssertionFromCertificateObject(cert *ClientCertificate) *ClientAssertion {
	assertion := &ClientAssertion{ClientCertificate: cert}
	return assertion
}

// GetJWT gets the assertion JWT from either the certificate or the JWT passed in.
func (assertion *ClientAssertion) GetJWT(authParams AuthParametersInternal) (string, error) {
	if assertion.ClientAssertionJWT == "" {
		if assertion.ClientCertificate == nil {
			return "", errors.New("no assertion or certificate found")
		}
		jwt, err := assertion.ClientCertificate.BuildJWT(authParams)
		if err != nil {
			return "", err
		}
		assertion.ClientAssertionJWT = jwt
		// Check if the assertion is built from an expired certificate
	} else if assertion.ClientCertificate != nil &&
		assertion.ClientCertificate.IsExpired() {
		jwt, err := assertion.ClientCertificate.BuildJWT(authParams)
		if err != nil {
			return "", err
		}
		assertion.ClientAssertionJWT = jwt
	}
	return assertion.ClientAssertionJWT, nil
}

var certHeader = map[string]interface{}{
	"alg": "RS256",
	"typ": "JWT",
}

// ClientCertificate consists of the parameters to create a assertion from certificate parameters, which include a thumbprint and private key.
type ClientCertificate struct {
	thumbprint string
	key        []byte
	expiresOn  int64
}

// CreateClientCertificate creates a ClientCertificate instance from the thumbprint and private key.
func CreateClientCertificate(thumbprint string, key []byte) *ClientCertificate {
	cert := &ClientCertificate{
		thumbprint: thumbprint,
		key:        key,
	}
	return cert
}

// IsExpired checks if the JWT created from the certificate is expired.
func (cert *ClientCertificate) IsExpired() bool {
	return time.Now().UTC().Unix() < cert.expiresOn
}

// BuildJWT builds a JWT assertion using the client certificate parameters.
// The parameters of the JWT are described in https://docs.microsoft.com/azure/active-directory/develop/active-directory-certificate-credentials .
func (cert *ClientCertificate) BuildJWT(authParams AuthParametersInternal) (string, error) {
	// CertificateExpirationTime is used when building an assertion JWT from a client certificate.
	const CertificateExpirationTime = 600

	now := time.Now().UTC().Unix()
	expiresOn := now + CertificateExpirationTime
	cert.expiresOn = expiresOn
	//The thumbprint is hex encoded, so we need to encode this to base64
	hexDecodedThumbprint, err := hex.DecodeString(cert.thumbprint)
	if err != nil {
		return "", err
	}
	//Updating the headers of the JWT
	certHeader["x5t"] = base64.StdEncoding.EncodeToString(hexDecodedThumbprint)
	//Adding the claims to the JWT
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"aud": authParams.Endpoints.TokenEndpoint,
		"exp": strconv.FormatInt(expiresOn, 10),
		"iss": authParams.ClientID,
		"jti": uuid.New().String(),
		"nbf": strconv.FormatInt(now, 10),
		"sub": authParams.ClientID,
	})
	token.Header = certHeader
	//Decoding the byte array of the private key to a PEM formatted block
	block, _ := pem.Decode(cert.key)
	//Parses a private key that can be used to sign the claims from the PEM block
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	//Signing the claims using the private key
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// OAuthResponseBase stores common information when sending a request to get a token.
type OAuthResponseBase struct {
	Error            string `json:"error"`
	SubError         string `json:"suberror"`
	ErrorDescription string `json:"error_description"`
	ErrorCodes       []int  `json:"error_codes"`
	CorrelationID    string `json:"correlation_id"`
	Claims           string `json:"claims"`

	AdditionalFields map[string]interface{}
}

var httpFailureCodes = map[int]string{
	404: "HTTP 404",
	500: "HTTP 500",
}

// CreateOAuthResponseBase creates a OAuthResponseBase instance from the HTTP client's response.
func CreateOAuthResponseBase(httpStatusCode int, responseData []byte) (OAuthResponseBase, error) {
	// if the status code corresponds to an error, throw the error
	if failMessage, ok := httpFailureCodes[httpStatusCode]; ok {
		return OAuthResponseBase{}, errors.New(failMessage)
	}

	payload := OAuthResponseBase{}
	err := json.Unmarshal(responseData, &payload)
	if err != nil {
		return OAuthResponseBase{}, err
	}
	//If the response consists of an error, throw that error
	if payload.Error != "" {
		return OAuthResponseBase{}, fmt.Errorf("%s: %s", payload.Error, payload.ErrorDescription)
	}
	return payload, nil
}

// GetOSPlatform gets the OS that the client using MSAL is running on.
// TODO(jdoak): Remove this.
func GetOSPlatform() string {
	h, _ := host.Info()
	return h.Platform
}

// GetOSVersion gets the OS version that the client using MSAL is running on.
// TODO(jdoak): Remove this.
func GetOSVersion() string {
	h, _ := host.Info()
	return h.PlatformVersion
}

// ConvertStrUnixToUTCTime converts a string representation of unix time to a UTC timestamp.
func ConvertStrUnixToUTCTime(unixTime string) (time.Time, error) {
	timeInt, err := strconv.ParseInt(unixTime, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(timeInt, 0).UTC(), nil
}

// DefaultScopeSeparator is used to convert a list of scopes to a string.
const DefaultScopeSeparator = " "

// ConcatenateScopes combines all scopes into one space-separated string.
func ConcatenateScopes(scopes []string) string {
	return strings.Join(scopes, DefaultScopeSeparator)
}

// SplitScopes splits a space-separated string of scopes to a list.
func SplitScopes(scopes string) []string {
	return strings.Split(scopes, DefaultScopeSeparator)
}

// GetStringKey does a lookup and returns the string at that value or an empty string.
func GetStringKey(j map[string]interface{}, key string) string {
	i := j[key]
	if i == nil {
		return ""
	}
	v, ok := i.(string)
	if !ok {
		return ""
	}
	return v
}

// DecodeJWT decodes a JWT and converts it to a byte array representing a JSON object
// Adapted from MSAL Python and https://stackoverflow.com/a/31971780 .
func DecodeJWT(data string) ([]byte, error) {
	if i := len(data) % 4; i != 0 {
		data += strings.Repeat("=", 4-i)
	}
	decodedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return decodedData, nil
}

// IDToken consists of all the information used to validate a user.
// https://docs.microsoft.com/azure/active-directory/develop/id-tokens .
type IDToken struct {
	PreferredUsername string `json:"preferred_username,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	Name              string `json:"name,omitempty"`
	Oid               string `json:"oid,omitempty"`
	TenantID          string `json:"tid,omitempty"`
	Subject           string `json:"sub,omitempty"`
	UPN               string `json:"upn,omitempty"`
	Email             string `json:"email,omitempty"`
	AlternativeID     string `json:"alternative_id,omitempty"`
	Issuer            string `json:"iss,omitempty"`
	Audience          string `json:"aud,omitempty"`
	ExpirationTime    int64  `json:"exp,omitempty"`
	IssuedAt          int64  `json:"iat,omitempty"`
	NotBefore         int64  `json:"nbf,omitempty"`
	RawToken          string

	AdditionalFields map[string]interface{}
}

// NewIDToken creates an ID token instance from a JWT.
func NewIDToken(jwt string) (IDToken, error) {
	jwtArr := strings.Split(jwt, ".")
	if len(jwtArr) < 2 {
		return IDToken{}, errors.New("id token returned from server is invalid")
	}
	jwtPart := jwtArr[1]
	jwtDecoded, err := DecodeJWT(jwtPart)
	if err != nil {
		return IDToken{}, err
	}
	idToken := IDToken{}
	err = json.Unmarshal(jwtDecoded, &idToken)
	if err != nil {
		return IDToken{}, err
	}
	idToken.RawToken = jwt
	return idToken, nil
}

// IsZero indicates if the IDToken is the zero value.
func (i IDToken) IsZero() bool {
	v := reflect.ValueOf(i)
	for i := 0; i < v.NumField(); i++ {
		if !v.Field(i).IsZero() {
			return false
		}
	}
	return true
}

// GetLocalAccountID extracts an account's local account ID from an ID token.
func (i IDToken) GetLocalAccountID() string {
	if i.Oid != "" {
		return i.Oid
	}
	return i.Subject
}

// Credential is an interface for cache entries such as access, refresh and ID tokens.
type Credential interface {
	Key() string
	GetSecret() string
}
