package requests

import (
	"github.com/markzuber/msalgo/internal/msalbase"
	"github.com/markzuber/msalgo/internal/wstrust"
)

// IWebRequestManager interface
type IWebRequestManager interface {
	GetUserRealm(authParameters *msalbase.AuthParametersInternal) (*msalbase.UserRealm, error)
	GetMex(federationMetadataURL string) (*wstrust.WsTrustMexDocument, error)
	GetWsTrustResponse(authParameters *msalbase.AuthParametersInternal, cloudAudienceURN string, endpoint *wstrust.WsTrustEndpoint) (*wstrust.WsTrustResponse, error)

	GetAccessTokenFromSamlGrant(authParameters *msalbase.AuthParametersInternal, samlGrant *wstrust.SamlTokenInfo) (*msalbase.TokenResponse, error)
	GetAccessTokenFromUsernamePassword(authParameters *msalbase.AuthParametersInternal) (*msalbase.TokenResponse, error)
	GetAccessTokenFromAuthCode(authParameters *msalbase.AuthParametersInternal, authCode string) (*msalbase.TokenResponse, error)
	GetAccessTokenFromRefreshToken(authParameters *msalbase.AuthParametersInternal, refreshToken string) (*msalbase.TokenResponse, error)
	GetAccessTokenWithCertificate(authParameters *msalbase.AuthParametersInternal, certificate *msalbase.ClientCertificate) (*msalbase.TokenResponse, error)
	GetDeviceCodeResult(authParameters *msalbase.AuthParametersInternal) (*msalbase.DeviceCodeResult, error)
	GetAccessTokenFromDeviceCodeResult(authParameters *msalbase.AuthParametersInternal, deviceCodeResult *msalbase.DeviceCodeResult) (*msalbase.TokenResponse, error)

	GetTenantDiscoveryResponse(openIDConfigurationEndpoint string) (*TenantDiscoveryResponse, error)
	GetAadinstanceDiscoveryResponse(authorityInfo *msalbase.AuthorityInfo) (*InstanceDiscoveryResponse, error)

	GetProviderConfigurationInformation(authParameters *msalbase.AuthParametersInternal) (*ProviderConfigurationInformation, error)
}
