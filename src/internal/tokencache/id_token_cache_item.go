// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

type idTokenCacheItem struct {
	HomeAccountID    string
	Environment      string
	RawClientInfo    string
	Realm            string
	CredentialType   string
	ClientID         string
	Secret           string
	TenantID         string
	AdditionalFields map[string]interface{}
}
