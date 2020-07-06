// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type refreshTokenCacheItem struct {
	HomeAccountID  string
	Environment    string
	RawClientInfo  string
	CredentialType string
	ClientID       string
	FamilyID       string
	Secret         string
}

func CreateRefreshTokenCacheItem(homeAccountID string,
	environment string,
	clientID string,
	refreshToken string,
	familyID string,
) *refreshTokenCacheItem {
	rt := &refreshTokenCacheItem{
		HomeAccountID:  homeAccountID,
		Environment:    environment,
		CredentialType: msalbase.CredentialTypeOauth2RefreshToken.ToString(),
		ClientID:       clientID,
		FamilyID:       familyID,
		Secret:         refreshToken,
	}
	return rt
}

func (rt *refreshTokenCacheItem) CreateKey() string {
	var fourth string
	if rt.FamilyID == "" {
		fourth = rt.ClientID
	} else {
		fourth = rt.FamilyID
	}
	keyParts := []string{rt.HomeAccountID, rt.Environment, rt.CredentialType, fourth}
	return strings.Join(keyParts, msalbase.CacheKeySeparator)
}

func (rt *refreshTokenCacheItem) GetSecret() string {
	return rt.Secret
}
