// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package storage

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

// Contract is the JSON structure that is written to any storage medium when serializing
// the internal cache. This design is shared between MSAL versions in many languages.
// This cannot be changed without design that includes other SDKs.
type Contract struct {
	AccessTokens  map[string]AccessToken      `json:"AccessToken"`
	RefreshTokens map[string]RefreshToken     `json:"RefreshToken"`
	IDTokens      map[string]IDToken          `json:"IdToken"`
	Accounts      map[string]msalbase.Account `json:"Account"`
	AppMetaData   map[string]AppMetaData      `json:"AppMetadata"`

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
		RefreshTokens:    make(map[string]RefreshToken, len(c.RefreshTokens)),
		IDTokens:         make(map[string]IDToken, len(c.IDTokens)),
		Accounts:         make(map[string]msalbase.Account, len(c.Accounts)),
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
	HomeAccountID                  string `json:"home_account_id,omitempty"`
	Environment                    string `json:"environment,omitempty"`
	Realm                          string `json:"realm,omitempty"`
	CredentialType                 string `json:"credential_type,omitempty"`
	ClientID                       string `json:"client_id,omitempty"`
	Secret                         string `json:"secret,omitempty"`
	Scopes                         string `json:"target,omitempty"`
	ExpiresOnUnixTimestamp         string `json:"expires_on,omitempty"`
	ExtendedExpiresOnUnixTimestamp string `json:"extended_expires_on,omitempty"`
	CachedAt                       string `json:"cached_at,omitempty"`

	AdditionalFields map[string]interface{}
}

// NewAccessToken is the constructor for AccessToken.
func NewAccessToken(homeID, env, realm, clientID string, cachedAt, expiresOn, extendedExpiresOn int64, scopes, token string) AccessToken {
	return AccessToken{
		HomeAccountID:                  homeID,
		Environment:                    env,
		Realm:                          realm,
		CredentialType:                 msalbase.CredentialTypeAccessToken,
		ClientID:                       clientID,
		Secret:                         token,
		Scopes:                         scopes,
		CachedAt:                       strconv.FormatInt(cachedAt, 10),
		ExpiresOnUnixTimestamp:         strconv.FormatInt(expiresOn, 10),
		ExtendedExpiresOnUnixTimestamp: strconv.FormatInt(extendedExpiresOn, 10),
	}
}

// Key outputs the key that can be used to uniquely look up this entry in a map.
func (a AccessToken) Key() string {
	return strings.Join(
		[]string{a.HomeAccountID, a.Environment, a.CredentialType, a.ClientID, a.Realm, a.Scopes},
		msalbase.CacheKeySeparator,
	)
}

// TODO(jdoak): These should be renamed to remove the "Get".  This is not just a
// replace across files.

func (a AccessToken) GetSecret() string {
	return a.Secret
}

func (a AccessToken) GetExpiresOn() string {
	return a.ExpiresOnUnixTimestamp
}

func (a AccessToken) GetScopes() string {
	return a.Scopes
}

// Validate validates that this AccessToken can be used.
func (a AccessToken) Validate() error {
	cachedAt, err := strconv.ParseInt(a.CachedAt, 10, 64)
	if err != nil {
		return fmt.Errorf("access token isn't valid, the cached at field is invalid: %w", err)
	}

	// TODO(jdoak): Fix all this Unix() stuff. We should be using time.Time() objects
	// and we can make it easy to do this across JSON borders.
	now := time.Now().Unix()
	if cachedAt > now {
		return errors.New("access token isn't valid, it was cached at a future time")
	}
	expiresOn, err := strconv.ParseInt(a.ExpiresOnUnixTimestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("access token isn't valid, the cached at field is invalid: %w", err)
	}
	if expiresOn <= now+300 {
		return fmt.Errorf("access token is expired")
	}
	return nil
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
		msalbase.CacheKeySeparator,
	)
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

// NewIDToken is the constructor for IDToken.
func NewIDToken(homeID, env, realm, clientID, idToken string) IDToken {
	return IDToken{
		HomeAccountID:  homeID,
		Environment:    env,
		Realm:          realm,
		CredentialType: msalbase.CredentialTypeIDToken,
		ClientID:       clientID,
		Secret:         idToken,
	}
}

// Key outputs the key that can be used to uniquely look up this entry in a map.
func (id IDToken) Key() string {
	return strings.Join(
		[]string{id.HomeAccountID, id.Environment, id.CredentialType, id.ClientID, id.Realm},
		msalbase.CacheKeySeparator,
	)
}

func (id IDToken) GetSecret() string {
	return id.Secret
}

// RefreshToken is the JSON representation of a MSAL refresh token for encoding to storage.
type RefreshToken struct {
	HomeAccountID  string `json:"home_account_id,omitempty"`
	Environment    string `json:"environment,omitempty"`
	CredentialType string `json:"credential_type,omitempty"`
	ClientID       string `json:"client_id,omitempty"`
	FamilyID       string `json:"family_id,omitempty"`
	Secret         string `json:"secret,omitempty"`
	Realm          string `json:"realm,omitempty"`
	Target         string `json:"target,omitempty"`

	AdditionalFields map[string]interface{}
}

// NewRefreshToken is the constructor for RefreshToken.
func NewRefreshToken(homeID, env, clientID, refreshToken, familyID string) RefreshToken {
	return RefreshToken{
		HomeAccountID:  homeID,
		Environment:    env,
		CredentialType: msalbase.CredentialTypeRefreshToken,
		ClientID:       clientID,
		FamilyID:       familyID,
		Secret:         refreshToken,
	}
}

// Key outputs the key that can be used to uniquely look up this entry in a map.
func (rt RefreshToken) Key() string {
	var fourth = rt.FamilyID
	if fourth == "" {
		fourth = rt.ClientID
	}

	return strings.Join(
		[]string{rt.HomeAccountID, rt.Environment, rt.CredentialType, fourth},
		msalbase.CacheKeySeparator,
	)
}

func (rt RefreshToken) GetSecret() string {
	return rt.Secret
}
