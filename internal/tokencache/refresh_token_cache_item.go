// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

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
