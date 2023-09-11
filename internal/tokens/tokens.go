// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokens

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
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

var null = []byte("null")

// UnmarshalJSON implements json.Unmarshaler.
func (i *IDToken) UnmarshalJSON(b []byte) error {
	if bytes.Equal(null, b) {
		return nil
	}

	// Because we have a custom unmarshaler, you
	// cannot directly call json.Unmarshal here. If you do, it will call this function
	// recursively until reach our recursion limit. We have to create a new type
	// that doesn't have this method in order to use json.Unmarshal.
	type idToken2 IDToken

	jwt := strings.Trim(string(b), `"`)
	jwtArr := strings.Split(jwt, ".")
	if len(jwtArr) < 2 {
		return errors.New("IDToken returned from server is invalid")
	}

	jwtPart := jwtArr[1]
	jwtDecoded, err := base64.RawURLEncoding.DecodeString(jwtPart)
	if err != nil {
		return fmt.Errorf("unable to unmarshal IDToken, problem decoding JWT: %w", err)
	}

	token := idToken2{}
	err = json.Unmarshal(jwtDecoded, &token)
	if err != nil {
		return fmt.Errorf("unable to unmarshal IDToken: %w", err)
	}
	token.RawToken = jwt

	*i = IDToken(token)
	return nil
}

// IsZero indicates if the IDToken is the zero value.
func (i IDToken) IsZero() bool {
	v := reflect.ValueOf(i)
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if !field.IsZero() {
			switch field.Kind() {
			case reflect.Map, reflect.Slice:
				if field.Len() == 0 {
					continue
				}
			}
			return false
		}
	}
	return true
}

// LocalAccountID extracts an account's local account ID from an ID token.
func (i IDToken) LocalAccountID() string {
	if i.Oid != "" {
		return i.Oid
	}
	return i.Subject
}
