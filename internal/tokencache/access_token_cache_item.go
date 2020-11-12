// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

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
