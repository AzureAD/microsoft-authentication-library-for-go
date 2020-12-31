// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"context"
	"net/url"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/wstrust"
	"github.com/stretchr/testify/mock"
)

type MockWebRequestManager struct {
	mock.Mock
}

func (mock *MockWebRequestManager) GetUserRealm(ctx context.Context, authParameters msalbase.AuthParametersInternal) (msalbase.UserRealm, error) {
	args := mock.Called(authParameters)
	return args.Get(0).(msalbase.UserRealm), args.Error(1)
}

func (mock *MockWebRequestManager) GetMex(ctx context.Context, federationMetadataURL string) (wstrust.MexDocument, error) {
	args := mock.Called(federationMetadataURL)
	return args.Get(0).(wstrust.MexDocument), args.Error(1)
}

func (mock *MockWebRequestManager) GetWsTrustResponse(ctx context.Context, authParameters msalbase.AuthParametersInternal, cloudAudienceURN string, endpoint wstrust.Endpoint) (wstrust.Response, error) {
	args := mock.Called(authParameters, cloudAudienceURN, endpoint)
	return args.Get(0).(wstrust.Response), args.Error(1)
}

func (mock *MockWebRequestManager) GetAccessTokenFromSamlGrant(ctx context.Context, authParameters msalbase.AuthParametersInternal, samlGrant wstrust.SamlTokenInfo) (msalbase.TokenResponse, error) {
	args := mock.Called(authParameters, samlGrant)
	return args.Get(0).(msalbase.TokenResponse), args.Error(1)
}

func (mock *MockWebRequestManager) GetAccessTokenFromUsernamePassword(ctx context.Context, authParameters msalbase.AuthParametersInternal) (msalbase.TokenResponse, error) {
	args := mock.Called(authParameters)
	return args.Get(0).(msalbase.TokenResponse), args.Error(1)
}

func (mock *MockWebRequestManager) GetAccessTokenFromAuthCode(ctx context.Context, authParameters msalbase.AuthParametersInternal, authCode, codeVerifier string, params url.Values) (msalbase.TokenResponse, error) {
	args := mock.Called(authParameters, authCode, codeVerifier, params)
	return args.Get(0).(msalbase.TokenResponse), args.Error(1)
}

func (mock *MockWebRequestManager) GetAccessTokenFromRefreshToken(ctx context.Context, authParameters msalbase.AuthParametersInternal, refreshToken string, params url.Values) (msalbase.TokenResponse, error) {
	args := mock.Called(authParameters, refreshToken, params)
	return args.Get(0).(msalbase.TokenResponse), args.Error(1)
}

func (mock *MockWebRequestManager) GetAccessTokenWithClientSecret(ctx context.Context, authParameters msalbase.AuthParametersInternal, clientSecret string) (msalbase.TokenResponse, error) {
	args := mock.Called(authParameters, clientSecret)
	return args.Get(0).(msalbase.TokenResponse), args.Error(1)
}

func (mock *MockWebRequestManager) GetAccessTokenWithAssertion(ctx context.Context, authParameters msalbase.AuthParametersInternal, assertion string) (msalbase.TokenResponse, error) {
	args := mock.Called(authParameters, assertion)
	return args.Get(0).(msalbase.TokenResponse), args.Error(1)
}

func (mock *MockWebRequestManager) GetDeviceCodeResult(ctx context.Context, authParameters msalbase.AuthParametersInternal) (msalbase.DeviceCodeResult, error) {
	args := mock.Called(authParameters)
	return args.Get(0).(msalbase.DeviceCodeResult), args.Error(1)
}

func (mock *MockWebRequestManager) GetAccessTokenFromDeviceCodeResult(ctx context.Context, authParameters msalbase.AuthParametersInternal, deviceCodeResult msalbase.DeviceCodeResult) (msalbase.TokenResponse, error) {
	args := mock.Called(authParameters, deviceCodeResult)
	return args.Get(0).(msalbase.TokenResponse), args.Error(1)
}

func (mock *MockWebRequestManager) GetTenantDiscoveryResponse(ctx context.Context, openIDConfigurationEndpoint string) (authority.TenantDiscoveryResponse, error) {
	args := mock.Called(openIDConfigurationEndpoint)
	return args.Get(0).(authority.TenantDiscoveryResponse), args.Error(1)
}

func (mock *MockWebRequestManager) GetAadinstanceDiscoveryResponse(ctx context.Context, authorityInfo msalbase.AuthorityInfo) (authority.InstanceDiscoveryResponse, error) {
	args := mock.Called(authorityInfo)
	return args.Get(0).(authority.InstanceDiscoveryResponse), args.Error(1)
}
