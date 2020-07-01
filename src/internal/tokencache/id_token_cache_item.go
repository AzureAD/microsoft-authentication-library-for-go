// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type idTokenCacheItem struct {
	HomeAccountID  string
	Environment    string
	Realm          string
	CredentialType string
	ClientID       string
	Secret         string
}

func CreateIDTokenCacheItem(homeAccountID string,
	environment string,
	realm string,
	clientID string,
	idToken string) *idTokenCacheItem {
	id := &idTokenCacheItem{
		HomeAccountID:  homeAccountID,
		Environment:    environment,
		Realm:          realm,
		CredentialType: msalbase.CredentialTypeOidcIDToken.ToString(),
		ClientID:       clientID,
		Secret:         idToken,
	}
	return id
}

func (id *idTokenCacheItem) CreateKey() string {
	keyParts := []string{id.HomeAccountID, id.Environment, id.CredentialType, id.ClientID, id.Realm}
	return strings.Join(keyParts, msalbase.CacheKeySeparator)
}
