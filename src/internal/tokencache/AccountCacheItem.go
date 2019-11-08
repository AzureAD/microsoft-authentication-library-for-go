// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

type accountCacheItem struct {
	HomeAccountID     string
	Environment       string
	RawClientInfo     string
	TenantID          string
	PreferredUsername string
	Name              string
	GivenName         string
	MiddleName        string
	FamilyName        string
	LocalAccountID    string
	AuthorityType     string
	AdditionalFields  map[string]interface{}
}
