// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

type refreshTokenCacheItem struct {
	HomeAccountID    string
	Environment      string
	RawClientInfo    string
	CredentialType   string
	ClientID         string
	Secret           string
	AdditionalFields map[string]interface{}
}
