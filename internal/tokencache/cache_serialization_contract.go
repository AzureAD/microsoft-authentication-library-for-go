// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

type cacheSerializationContract struct {
	// TODO(jdoak): These values are currently pointers, but I don't think they
	// need to be. I need to confirm that if a key exists, a value should exist.
	// If that is the case, then these can be converted to non-pointers.
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
