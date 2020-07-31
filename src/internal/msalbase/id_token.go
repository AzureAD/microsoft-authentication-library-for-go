// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"encoding/json"
	"errors"
	"strings"
)

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
}

func CreateIDToken(jwt string) (*IDToken, error) {
	jwtArr := strings.Split(jwt, ".")
	if len(jwtArr) < 2 {
		return nil, errors.New("ID Token returned from server is invalid")
	}
	jwtPart := jwtArr[1]
	jwtDecoded, err := DecodeJWT(jwtPart)
	if err != nil {
		return nil, err
	}
	idToken := &IDToken{}
	err = json.Unmarshal(jwtDecoded, idToken)
	if err != nil {
		return nil, err
	}
	idToken.RawToken = jwt
	return idToken, nil
}

func (idToken *IDToken) GetLocalAccountID() string {
	if idToken.Oid != "" {
		return idToken.Oid
	} else {
		return idToken.Subject
	}
}
