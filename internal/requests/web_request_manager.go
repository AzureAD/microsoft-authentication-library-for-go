// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

/*
import (
	"context"
	"net/url"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/wstrust"
)

// WebRequestManager interface
type WebRequestManager interface {
	GetUserRealm(ctx context.Context, authParameters msalbase.AuthParametersInternal) (msalbase.UserRealm, error)
	GetMex(ctx context.Context, federationMetadataURL string) (wstrust.MexDocument, error)
	GetWsTrustResponse(ctx context.Context, authParameters msalbase.AuthParametersInternal, cloudAudienceURN string, endpoint wstrust.Endpoint) (wstrust.Response, error)
	GetAccessTokenFromSamlGrant(ctx context.Context, authParameters msalbase.AuthParametersInternal, samlGrant wstrust.SamlTokenInfo) (msalbase.TokenResponse, error)
	GetAccessTokenFromUsernamePassword(ctx context.Context, authParameters msalbase.AuthParametersInternal) (msalbase.TokenResponse, error)
	GetAccessTokenFromAuthCode(ctx context.Context, authParameters msalbase.AuthParametersInternal, authCode string, codeVerifier string, params url.Values) (msalbase.TokenResponse, error)
	GetAccessTokenFromRefreshToken(ctx context.Context, authParameters msalbase.AuthParametersInternal, refreshToken string, params url.Values) (msalbase.TokenResponse, error)
	GetAccessTokenWithClientSecret(ctx context.Context, authParameters msalbase.AuthParametersInternal, clientSecret string) (msalbase.TokenResponse, error)
	GetAccessTokenWithAssertion(ctx context.Context, authParameters msalbase.AuthParametersInternal, assertion string) (msalbase.TokenResponse, error)
	GetDeviceCodeResult(ctx context.Context, authParameters msalbase.AuthParametersInternal) (msalbase.DeviceCodeResult, error)
	GetAccessTokenFromDeviceCodeResult(ctx context.Context, authParameters msalbase.AuthParametersInternal, deviceCodeResult msalbase.DeviceCodeResult) (msalbase.TokenResponse, error)
	GetTenantDiscoveryResponse(ctx context.Context, openIDConfigurationEndpoint string) (TenantDiscoveryResponse, error)
	GetAadinstanceDiscoveryResponse(ctx context.Context, authorityInfo msalbase.AuthorityInfo) (InstanceDiscoveryResponse, error)
}
*/
