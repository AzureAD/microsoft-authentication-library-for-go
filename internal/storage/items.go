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

type cacheSerializationContract struct {
	AccessTokens  map[string]accessTokenCacheItem  `json:"AccessToken"`
	RefreshTokens map[string]refreshTokenCacheItem `json:"RefreshToken"`
	IDTokens      map[string]idTokenCacheItem      `json:"IdToken"`
	Accounts      map[string]msalbase.Account      `json:"Account"`
	AppMetadata   map[string]appMetadata           `json:"AppMetadata"`

	AdditionalFields map[string]interface{}
}

// TODO(jdoak): I've removed all make() stuff. This should get removed
// in a future update.
func createCacheSerializationContract() *cacheSerializationContract {
	return &cacheSerializationContract{}
}

type accessTokenCacheItem struct {
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

func createAccessTokenCacheItem(homeID, env, realm, clientID string, cachedAt, expiresOn, extendedExpiresOn int64, scopes, token string) accessTokenCacheItem {
	return accessTokenCacheItem{
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

func (a accessTokenCacheItem) CreateKey() string {
	return strings.Join(
		[]string{a.HomeAccountID, a.Environment, a.CredentialType, a.ClientID, a.Realm, a.Scopes},
		msalbase.CacheKeySeparator,
	)
}

func (a accessTokenCacheItem) GetSecret() string {
	return a.Secret
}

func (a accessTokenCacheItem) GetExpiresOn() string {
	return a.ExpiresOnUnixTimestamp
}

func (a accessTokenCacheItem) GetScopes() string {
	return a.Scopes
}

// Validate validates that this accessTokenCacheItem can be used.
func (a accessTokenCacheItem) Validate() error {
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

type appMetadata struct {
	FamilyID    string `json:"family_id,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
	Environment string `json:"environment,omitempty"`

	AdditionalFields map[string]interface{}
}

func createAppMetadata(familyID, clientID, environment string) appMetadata {
	return appMetadata{
		FamilyID:    familyID,
		ClientID:    clientID,
		Environment: environment,
	}
}

func (appMeta appMetadata) CreateKey() string {
	return strings.Join(
		[]string{"appmetadata", appMeta.Environment, appMeta.ClientID},
		msalbase.CacheKeySeparator,
	)
}

type idTokenCacheItem struct {
	HomeAccountID    string `json:"home_account_id,omitempty"`
	Environment      string `json:"environment,omitempty"`
	Realm            string `json:"realm,omitempty"`
	CredentialType   string `json:"credential_type,omitempty"`
	ClientID         string `json:"client_id,omitempty"`
	Secret           string `json:"secret,omitempty"`
	AdditionalFields map[string]interface{}
}

func createIDTokenCacheItem(homeID, env, realm, clientID, idToken string) idTokenCacheItem {
	return idTokenCacheItem{
		HomeAccountID:  homeID,
		Environment:    env,
		Realm:          realm,
		CredentialType: msalbase.CredentialTypeIDToken,
		ClientID:       clientID,
		Secret:         idToken,
	}
}

func (id idTokenCacheItem) CreateKey() string {
	return strings.Join(
		[]string{id.HomeAccountID, id.Environment, id.CredentialType, id.ClientID, id.Realm},
		msalbase.CacheKeySeparator,
	)
}

func (id idTokenCacheItem) GetSecret() string {
	return id.Secret
}

type refreshTokenCacheItem struct {
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

func createRefreshTokenCacheItem(homeID, env, clientID, refreshToken, familyID string) refreshTokenCacheItem {
	return refreshTokenCacheItem{
		HomeAccountID:  homeID,
		Environment:    env,
		CredentialType: msalbase.CredentialTypeRefreshToken,
		ClientID:       clientID,
		FamilyID:       familyID,
		Secret:         refreshToken,
	}
}

func (rt refreshTokenCacheItem) CreateKey() string {
	var fourth = rt.FamilyID
	if fourth == "" {
		fourth = rt.ClientID
	}

	return strings.Join(
		[]string{rt.HomeAccountID, rt.Environment, rt.CredentialType, fourth},
		msalbase.CacheKeySeparator,
	)
}

func (rt refreshTokenCacheItem) GetSecret() string {
	return rt.Secret
}
