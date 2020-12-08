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

type CacheSerializationContract struct {
	AccessTokens  map[string]AccessTokenCacheItem  `json:"AccessToken"`
	RefreshTokens map[string]RefreshTokenCacheItem `json:"RefreshToken"`
	IDTokens      map[string]IDTokenCacheItem      `json:"IdToken"`
	Accounts      map[string]msalbase.Account      `json:"Account"`
	AppMetadata   map[string]AppMetadata           `json:"AppMetadata"`

	AdditionalFields map[string]interface{}
}

// TODO(jdoak): I've removed all make() stuff. This should get removed
// in a future update.
func CreateCacheSerializationContract() *CacheSerializationContract {
	return &CacheSerializationContract{}
}

// copy returns a copy of the CacheSerializationContract.
func (c *CacheSerializationContract) copy() *CacheSerializationContract {
	n := &CacheSerializationContract{
		AccessTokens:     make(map[string]AccessTokenCacheItem, len(c.AccessTokens)),
		RefreshTokens:    make(map[string]RefreshTokenCacheItem, len(c.RefreshTokens)),
		IDTokens:         make(map[string]IDTokenCacheItem, len(c.IDTokens)),
		Accounts:         make(map[string]msalbase.Account, len(c.Accounts)),
		AppMetadata:      make(map[string]AppMetadata, len(c.AppMetadata)),
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
	for k, v := range c.AppMetadata {
		n.AppMetadata[k] = v
	}
	for k, v := range c.AdditionalFields {
		n.AdditionalFields[k] = v
	}
	return n
}

type AccessTokenCacheItem struct {
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

func createAccessTokenCacheItem(homeID, env, realm, clientID string, cachedAt, expiresOn, extendedExpiresOn int64, scopes, token string) AccessTokenCacheItem {
	return AccessTokenCacheItem{
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

func (a AccessTokenCacheItem) CreateKey() string {
	return strings.Join(
		[]string{a.HomeAccountID, a.Environment, a.CredentialType, a.ClientID, a.Realm, a.Scopes},
		msalbase.CacheKeySeparator,
	)
}

func (a AccessTokenCacheItem) GetSecret() string {
	return a.Secret
}

func (a AccessTokenCacheItem) GetExpiresOn() string {
	return a.ExpiresOnUnixTimestamp
}

func (a AccessTokenCacheItem) GetScopes() string {
	return a.Scopes
}

// Validate validates that this AccessTokenCacheItem can be used.
func (a AccessTokenCacheItem) Validate() error {
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

type AppMetadata struct {
	FamilyID    string `json:"family_id,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
	Environment string `json:"environment,omitempty"`

	AdditionalFields map[string]interface{}
}

func CreateAppMetadata(familyID, clientID, environment string) AppMetadata {
	return AppMetadata{
		FamilyID:    familyID,
		ClientID:    clientID,
		Environment: environment,
	}
}

func (appMeta AppMetadata) CreateKey() string {
	return strings.Join(
		[]string{"AppMetadata", appMeta.Environment, appMeta.ClientID},
		msalbase.CacheKeySeparator,
	)
}

type IDTokenCacheItem struct {
	HomeAccountID    string `json:"home_account_id,omitempty"`
	Environment      string `json:"environment,omitempty"`
	Realm            string `json:"realm,omitempty"`
	CredentialType   string `json:"credential_type,omitempty"`
	ClientID         string `json:"client_id,omitempty"`
	Secret           string `json:"secret,omitempty"`
	AdditionalFields map[string]interface{}
}

func CreateIDTokenCacheItem(homeID, env, realm, clientID, idToken string) IDTokenCacheItem {
	return IDTokenCacheItem{
		HomeAccountID:  homeID,
		Environment:    env,
		Realm:          realm,
		CredentialType: msalbase.CredentialTypeIDToken,
		ClientID:       clientID,
		Secret:         idToken,
	}
}

func (id IDTokenCacheItem) CreateKey() string {
	return strings.Join(
		[]string{id.HomeAccountID, id.Environment, id.CredentialType, id.ClientID, id.Realm},
		msalbase.CacheKeySeparator,
	)
}

func (id IDTokenCacheItem) GetSecret() string {
	return id.Secret
}

type RefreshTokenCacheItem struct {
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

func CreateRefreshTokenCacheItem(homeID, env, clientID, refreshToken, familyID string) RefreshTokenCacheItem {
	return RefreshTokenCacheItem{
		HomeAccountID:  homeID,
		Environment:    env,
		CredentialType: msalbase.CredentialTypeRefreshToken,
		ClientID:       clientID,
		FamilyID:       familyID,
		Secret:         refreshToken,
	}
}

func (rt RefreshTokenCacheItem) CreateKey() string {
	var fourth = rt.FamilyID
	if fourth == "" {
		fourth = rt.ClientID
	}

	return strings.Join(
		[]string{rt.HomeAccountID, rt.Environment, rt.CredentialType, fourth},
		msalbase.CacheKeySeparator,
	)
}

func (rt RefreshTokenCacheItem) GetSecret() string {
	return rt.Secret
}
