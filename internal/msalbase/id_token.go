// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"errors"
	"reflect"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/json"
)

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
