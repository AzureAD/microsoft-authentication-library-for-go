// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/wstrust"
)

// WebRequestManager interface
type WebRequestManager interface {
	GetUserRealm(authParameters *msalbase.AuthParametersInternal) (*msalbase.UserRealm, error)
	GetMex(federationMetadataURL string) (*wstrust.MexDocument, error)
	GetWsTrustResponse(authParameters *msalbase.AuthParametersInternal, cloudAudienceURN string, endpoint *wstrust.Endpoint) (*wstrust.Response, error)
	GetAccessTokenFromSamlGrant(authParameters *msalbase.AuthParametersInternal, samlGrant *wstrust.SamlTokenInfo) (*msalbase.TokenResponse, error)
	GetAccessTokenFromUsernamePassword(authParameters *msalbase.AuthParametersInternal) (*msalbase.TokenResponse, error)
	GetAccessTokenFromAuthCode(authParameters *msalbase.AuthParametersInternal, authCode string, codeVerifier string, params map[string]string) (*msalbase.TokenResponse, error)
	GetAccessTokenFromRefreshToken(authParameters *msalbase.AuthParametersInternal, refreshToken string, params map[string]string) (*msalbase.TokenResponse, error)
	GetAccessTokenWithClientSecret(authParameters *msalbase.AuthParametersInternal, clientSecret string) (*msalbase.TokenResponse, error)
	GetAccessTokenWithAssertion(authParameters *msalbase.AuthParametersInternal, assertion string) (*msalbase.TokenResponse, error)
	GetDeviceCodeResult(authParameters *msalbase.AuthParametersInternal) (*msalbase.DeviceCodeResult, error)
	GetAccessTokenFromDeviceCodeResult(authParameters *msalbase.AuthParametersInternal, deviceCodeResult *msalbase.DeviceCodeResult) (*msalbase.TokenResponse, error)
	GetTenantDiscoveryResponse(openIDConfigurationEndpoint string) (*TenantDiscoveryResponse, error)
	GetAadinstanceDiscoveryResponse(authorityInfo *msalbase.AuthorityInfo) (*InstanceDiscoveryResponse, error)
}
