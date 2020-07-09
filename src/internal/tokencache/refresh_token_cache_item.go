// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type refreshTokenCacheItem struct {
	HomeAccountID    string
	Environment      string
	CredentialType   string
	ClientID         string
	FamilyID         string
	Secret           string
	additionalFields map[string]interface{}
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

func (rt *refreshTokenCacheItem) populateFromJSONMap(j map[string]interface{}) error {
	rt.HomeAccountID = msalbase.ExtractExistingOrEmptyString(j, "home_account_id")
	rt.Environment = msalbase.ExtractExistingOrEmptyString(j, "environment")
	rt.CredentialType = msalbase.ExtractExistingOrEmptyString(j, "credential_type")
	rt.ClientID = msalbase.ExtractExistingOrEmptyString(j, "client_id")
	rt.FamilyID = msalbase.ExtractExistingOrEmptyString(j, "family_id")
	rt.Secret = msalbase.ExtractExistingOrEmptyString(j, "secret")
	rt.additionalFields = j
	return nil
}
