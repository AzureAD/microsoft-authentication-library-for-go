// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

const (
	// CacheKeySeparator is used in creating the keys of the cache.
	CacheKeySeparator = "-"

	// Credential Types.

	CredentialTypeRefreshToken = "RefreshToken"
	CredentialTypeAccessToken  = "AccessToken"
	CredentialTypeIDToken      = "IDToken"

	// Authority Types.

	MSSTS = "MSSTS"
	ADFS  = "ADFS"
	B2C   = "B2C"

	// Grant Types.

	PasswordGrant         = "password"
	SAMLV1Grant           = "urn:ietf:params:oauth:grant-type:saml1_1-bearer"
	SAMLV2Grant           = "urn:ietf:params:oauth:grant-type:saml2-bearer"
	DeviceCodeGrant       = "device_code"
	AuthCodeGrant         = "authorization_code"
	RefreshTokenGrant     = "refresh_token"
	ClientCredentialGrant = "client_credentials"
	ClientAssertionGrant  = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// Endpoints.

	AuthorizationEndpoint     = "https://%v/%v/oauth2/v2.0/authorize"
	InstanceDiscoveryEndpoint = "https://%v/common/discovery/instance?%v"
	DefaultHost               = "login.microsoftonline.com"

	// HTTP Headers.

	ProductHeaderName                    = "x-client-SKU"
	ProductHeaderValue                   = "MSAL.Go"
	OSHeaderName                         = "x-client-OS"
	CorrelationIDHeaderName              = "client-request-id"
	ReqCorrelationIDInResponseHeaderName = "return-client-request-id"
)
