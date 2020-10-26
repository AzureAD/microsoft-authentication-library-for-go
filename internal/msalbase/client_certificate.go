// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strconv"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	uuid "github.com/google/uuid"
)

var certHeader = map[string]interface{}{
	"alg": "RS256",
	"typ": "JWT",
}

// ClientCertificate consists of the parameters to create a assertion from certificate parameters, which include a thumbprint and private key
type ClientCertificate struct {
	thumbprint string
	key        []byte
	expiresOn  int64
}

// CreateClientCertificate creates a ClientCertificate instance from the thumbprint and private key
func CreateClientCertificate(thumbprint string, key []byte) *ClientCertificate {
	cert := &ClientCertificate{
		thumbprint: thumbprint,
		key:        key,
	}
	return cert
}

// IsExpired checks if the JWT created from the certificate is expired
func (cert *ClientCertificate) IsExpired() bool {
	return time.Now().UTC().Unix() < cert.expiresOn
}

// BuildJWT builds a JWT assertion using the client certificate parameters
// The parameters of the JWT are described in https://docs.microsoft.com/azure/active-directory/develop/active-directory-certificate-credentials
func (cert *ClientCertificate) BuildJWT(authParams *AuthParametersInternal) (string, error) {
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
