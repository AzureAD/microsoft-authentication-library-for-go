// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

//List of all constants used throughout MSAL Go
const (
	//DefaultAuthCodeResponseType is the response type for authorization code requests
	DefaultAuthCodeResponseType = "code"

	//DefaultScopeSeparator is used to convert a list of scopes to a string
	DefaultScopeSeparator = " "

	//IntervalAddition is used in device code requests to increase the polling interval if there is a slow down error
	IntervalAddition = 5

	//CertificateExpirationTime is used when building an assertion JWT from a client certificate
	CertificateExpirationTime = 600

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

	//Grant Types
	PasswordGrant         = "password"
	SAMLV1Grant           = "urn:ietf:params:oauth:grant-type:saml1_1-bearer"
	SAMLV2Grant           = "urn:ietf:params:oauth:grant-type:saml2-bearer"
	DeviceCodeGrant       = "device_code"
	AuthCodeGrant         = "authorization_code"
	RefreshTokenGrant     = "refresh_token"
	ClientCredentialGrant = "client_credentials"
	ClientAssertionGrant  = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	//Endpoints
	AuthorizationEndpoint     = "https://%v/%v/oauth2/v2.0/authorize"
	InstanceDiscoveryEndpoint = "https://%v/common/discovery/instance?%v"
	DefaultHost               = "login.microsoftonline.com"

	SoapActionWSTrust2005 = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue"
	SoapActionDefault     = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"
)
