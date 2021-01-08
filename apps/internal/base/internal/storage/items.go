// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package storage

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
)

// Contract is the JSON structure that is written to any storage medium when serializing
// the internal cache. This design is shared between MSAL versions in many languages.
// This cannot be changed without design that includes other SDKs.
type Contract struct {
	AccessTokens  map[string]AccessToken               `json:"AccessToken"`
	RefreshTokens map[string]accesstokens.RefreshToken `json:"RefreshToken"`
	IDTokens      map[string]IDToken                   `json:"IdToken"`
	Accounts      map[string]shared.Account            `json:"Account"`
	AppMetaData   map[string]AppMetaData               `json:"AppMetadata"`

	AdditionalFields map[string]interface{}
}

// NewContract is the constructor for Contract.
func NewContract() *Contract {
	return &Contract{}
}

// copy returns a copy of the Contract.
func (c *Contract) copy() *Contract {
	n := &Contract{
		AccessTokens:     make(map[string]AccessToken, len(c.AccessTokens)),
		RefreshTokens:    make(map[string]accesstokens.RefreshToken, len(c.RefreshTokens)),
		IDTokens:         make(map[string]IDToken, len(c.IDTokens)),
		Accounts:         make(map[string]shared.Account, len(c.Accounts)),
		AppMetaData:      make(map[string]AppMetaData, len(c.AppMetaData)),
		AdditionalFields: make(map[string]interface{}, len(c.AdditionalFields)),
	}
	for k, v := range c.AccessTokens {
		n.AccessTokens[k] = v
	}
	for k, v := range c.RefreshTokens {
		n.RefreshTokens[k] = v
	}
	for k, v := range c.IDTokens {
		n.IDTokens[k] = v
	}
	for k, v := range c.Accounts {
		n.Accounts[k] = v
	}
	for k, v := range c.AppMetaData {
		n.AppMetaData[k] = v
	}
	for k, v := range c.AdditionalFields {
		n.AdditionalFields[k] = v
	}
	return n
}

// AccessToken is the JSON representation of a MSAL access token for encoding to storage.
type AccessToken struct {
	HomeAccountID  string `json:"home_account_id,omitempty"`
	Environment    string `json:"environment,omitempty"`
	Realm          string `json:"realm,omitempty"`
	CredentialType string `json:"credential_type,omitempty"`
	ClientID       string `json:"client_id,omitempty"`
	Secret         string `json:"secret,omitempty"`
	Scopes         string `json:"target,omitempty"`
	// TODO(jdoak): This should probably be a wrapper around time.Time that json marshals.
	ExpiresOn internalTime.Unix `json:"expires_on,omitempty"`
	// TODO(jdoak): This should probably be a wrapper around time.Time that json marshals.
	ExtendedExpiresOn internalTime.Unix `json:"extended_expires_on,omitempty"`
	// TODO(jdoak): This should probably be a wrapper around time.Time that json marshals.
	CachedAt internalTime.Unix `json:"cached_at,omitempty"`

	AdditionalFields map[string]interface{}
}

// NewAccessToken is the constructor for AccessToken.
func NewAccessToken(homeID, env, realm, clientID string, cachedAt, expiresOn, extendedExpiresOn time.Time, scopes, token string) AccessToken {
	return AccessToken{
		HomeAccountID:     homeID,
		Environment:       env,
		Realm:             realm,
		CredentialType:    "AccessToken",
		ClientID:          clientID,
		Secret:            token,
		Scopes:            scopes,
		CachedAt:          internalTime.Unix{T: cachedAt.UTC()},
		ExpiresOn:         internalTime.Unix{T: expiresOn.UTC()},
		ExtendedExpiresOn: internalTime.Unix{T: extendedExpiresOn.UTC()},
	}
}

// Key outputs the key that can be used to uniquely look up this entry in a map.
func (a AccessToken) Key() string {
	return strings.Join(
		[]string{a.HomeAccountID, a.Environment, a.CredentialType, a.ClientID, a.Realm, a.Scopes},
		shared.CacheKeySeparator,
	)
}

// Validate validates that this AccessToken can be used.
func (a AccessToken) Validate() error {
	// TODO(jdoak): Fix all this Unix() stuff. We should be using time.Time() objects
	// and we can make it easy to do this across JSON borders.
	if a.CachedAt.T.After(time.Now()) {
		return errors.New("access token isn't valid, it was cached at a future time")
	}
	if a.ExpiresOn.T.Before(time.Now().Add(5 * time.Minute)) {
		return fmt.Errorf("access token is expired")
	}
	if a.CachedAt.T.IsZero() {
		return fmt.Errorf("access token does not have CachedAt set")
	}
	return nil
}

// IDToken is the JSON representation of an MSAL id token for encoding to storage.
type IDToken struct {
	HomeAccountID    string `json:"home_account_id,omitempty"`
	Environment      string `json:"environment,omitempty"`
	Realm            string `json:"realm,omitempty"`
	CredentialType   string `json:"credential_type,omitempty"`
	ClientID         string `json:"client_id,omitempty"`
	Secret           string `json:"secret,omitempty"`
	AdditionalFields map[string]interface{}
}

// runtime check that makes sure IDToken hasn't added any fields not covered in IsZero().
// TODO(someone): This should get auto-generated probably.
func _() {
	valid := map[string]bool{
		"HomeAccountID":    true,
		"Environment":      true,
		"Realm":            true,
		"CredentialType":   true,
		"ClientID":         true,
		"Secret":           true,
		"AdditionalFields": true,
	}
	t := reflect.TypeOf(IDToken{})
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !valid[f.Name] {
			panic(fmt.Sprintf("storage.IDToken has new field %q, which must be added to .IsZero()", f.Name))
		}
	}
}

// IsZero determines if IDToken is the zero value.
func (i IDToken) IsZero() bool {
	switch {
	case i.HomeAccountID != "":
		return false
	case i.Environment != "":
		return false
	case i.Realm != "":
		return false
	case i.CredentialType != "":
		return false
	case i.ClientID != "":
		return false
	case i.Secret != "":
		return false
	case i.AdditionalFields != nil:
		return false
	}
	return true
}

// NewIDToken is the constructor for IDToken.
func NewIDToken(homeID, env, realm, clientID, idToken string) IDToken {
	return IDToken{
		HomeAccountID:  homeID,
		Environment:    env,
		Realm:          realm,
		CredentialType: "IDToken",
		ClientID:       clientID,
		Secret:         idToken,
	}
}

// Key outputs the key that can be used to uniquely look up this entry in a map.
func (id IDToken) Key() string {
	return strings.Join(
		[]string{id.HomeAccountID, id.Environment, id.CredentialType, id.ClientID, id.Realm},
		shared.CacheKeySeparator,
	)
}

// AppMetaData is the JSON representation of application metadata for encoding to storage.
type AppMetaData struct {
	FamilyID    string `json:"family_id,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
	Environment string `json:"environment,omitempty"`

	AdditionalFields map[string]interface{}
}

// NewAppMetaData is the constructor for AppMetaData.
func NewAppMetaData(familyID, clientID, environment string) AppMetaData {
	return AppMetaData{
		FamilyID:    familyID,
		ClientID:    clientID,
		Environment: environment,
	}
}

// Key outputs the key that can be used to uniquely look up this entry in a map.
func (a AppMetaData) Key() string {
	return strings.Join(
		[]string{"AppMetaData", a.Environment, a.ClientID},
		shared.CacheKeySeparator,
	)
}
