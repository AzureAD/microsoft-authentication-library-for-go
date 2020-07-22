// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"strconv"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	uuid "github.com/google/uuid"
)

type certificateHeader struct {
	Algorithm  string `json:"alg"`
	Type       string `json:"typ"`
	Thumbprint string `json:"x5t"`
}

var certHeader = map[string]interface{}{
	"alg": "RS256",
	"typ": "JWT",
}

type certificatePayload struct {
	Audience   string `json:"aud"`
	Expiration string `json:"exp"`
	Issuer     string `json:"iss"`
	GUID       string `json:"jti"`
	NotBefore  string `json:"nbf"`
	Subject    string `json:"sub"`
}

type ClientCertificate struct {
	thumbprint  string
	key         []byte
	certHeader  *certificateHeader
	certPayload *certificatePayload
}

func (cert *ClientCertificate) buildJWT(authParams *AuthParametersInternal,
	tokenEndpoint string) (string, error) {
	now := time.Now().UTC().Unix()
	expiresOn := now + 600
	certHeader["x5t"] = cert.thumbprint
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"aud": tokenEndpoint,
		"exp": strconv.FormatInt(expiresOn, 10),
		"iss": authParams.ClientID,
		"jti": uuid.New().String(),
		"nbf": strconv.FormatInt(now, 10),
		"sub": authParams.ClientID,
	})
	token.Header = certHeader
	tokenString, err := token.SignedString(cert.key)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
