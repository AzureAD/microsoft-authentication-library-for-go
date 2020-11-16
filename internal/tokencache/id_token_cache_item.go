// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

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
