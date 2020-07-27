// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

//DefaultAuthCodeResponseType is the response type for authorization code requests
const (
	DefaultAuthCodeResponseType = "code"

	//DefaultScopeSeparator is used to convert a list of scopes to a string
	DefaultScopeSeparator = " "

	//IntervalAddition is used in device code requests to increase the polling interval if there is a slow down error
	IntervalAddition = 5

	//CacheKeySeparator is used in creating the keys of the cache
	CacheKeySeparator = "-"

	//AppMetadataCacheID is a part of the cache key for App Metadata items
	AppMetadataCacheID = "appmetadata"

	//JSON Cache Keys
	JSONHomeAccountID  = "home_account_id"
	JSONEnvironment    = "environment"
	JSONRealm          = "realm"
	JSONLocalAccountID = "local_account_id"
	JSONAuthorityType  = "authority_type"
	JSONUsername       = "username"
	JSONClientInfo     = "client_info"
	JSONAlternativeID  = "alternative_account_id"
	JSONGivenName      = "given_name"
	JSONFamilyName     = "family_name"
	JSONName           = "name"
	JSONMiddleName     = "middle_name"
	JSONClientID       = "client_id"
	JSONCredentialType = "credential_type"
	JSONSecret         = "secret"
	JSONTarget         = "target"
	JSONCachedAt       = "cached_at"
	JSONExpiresOn      = "expires_on"
	JSONExtExpiresOn   = "extended_expires_on"
	JSONFamilyID       = "family_id"

	//Credential Types
	CredentialTypeRefreshToken = "RefreshToken"
	CredentialTypeAccessToken  = "AccessToken"
	CredentialTypeIDToken      = "IDToken"

	//Authority Types
	MSSTS = "MSSTS"
	ADFS  = "ADFS"
	B2C   = "B2C"
)
