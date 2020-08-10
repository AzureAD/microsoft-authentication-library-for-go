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

type ClientCertificate struct {
	thumbprint string
	key        []byte
	expiresOn  int64
}

func CreateClientCertificate(thumbprint string, key []byte) *ClientCertificate {
	cert := &ClientCertificate{
		thumbprint: thumbprint,
		key:        key,
	}
	return cert
}

func (cert *ClientCertificate) IsExpired() bool {
	return time.Now().UTC().Unix() < cert.expiresOn
}

func (cert *ClientCertificate) BuildJWT(authParams *AuthParametersInternal) (string, error) {
	now := time.Now().UTC().Unix()
	expiresOn := now + 600
	cert.expiresOn = expiresOn
	hexDecodedThumbprint, err := hex.DecodeString(cert.thumbprint)
	if err != nil {
		return "", err
	}
	certHeader["x5t"] = base64.StdEncoding.EncodeToString(hexDecodedThumbprint)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"aud": authParams.Endpoints.TokenEndpoint,
		"exp": strconv.FormatInt(expiresOn, 10),
		"iss": authParams.ClientID,
		"jti": uuid.New().String(),
		"nbf": strconv.FormatInt(now, 10),
		"sub": authParams.ClientID,
	})
	token.Header = certHeader
	block, _ := pem.Decode(cert.key)
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
