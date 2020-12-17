// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/json"
	jwt "github.com/dgrijalva/jwt-go"
	uuid "github.com/google/uuid"
)

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

type accessTokenProvider interface {
	GetSecret() string
	GetExpiresOn() string
	GetScopes() string
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

// ConvertStrUnixToUTCTime converts a string representation of unix time to a UTC timestamp.
func ConvertStrUnixToUTCTime(unixTime string) (time.Time, error) {
	timeInt, err := strconv.ParseInt(unixTime, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(timeInt, 0).UTC(), nil
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
	return base64.StdEncoding.DecodeString(data)
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
