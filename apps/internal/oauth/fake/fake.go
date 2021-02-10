// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package fake

import (
	"context"
	"errors"
	"fmt"
	"time"

	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/wstrust"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/wstrust/defs"
)

// ResolveEndpoints is a fake implementation of the oauth.resolveEndpointer interface.
type ResolveEndpoints struct {
	// Set this to true to have all APIs return an error.
	Err bool

	// fake result to return
	Endpoints authority.Endpoints
}

func (f ResolveEndpoints) ResolveEndpoints(ctx context.Context, authorityInfo authority.Info, userPrincipalName string) (authority.Endpoints, error) {
	if f.Err {
		return authority.Endpoints{}, errors.New("error")
	}
	return f.Endpoints, nil
}

// AccessTokens is a fake implementation of the oauth.accessTokens interface.
type AccessTokens struct {
	// Set this to true to have all APIs return an error.
	Err bool

	// Result is for use with FromDeviceCodeResult. On each call it returns
	// the next item in this slice. They must be either an error or nil.
	Result []error
	Next   int

	// fake result to return
	AccessToken accesstokens.TokenResponse

	// fake result to return
	DeviceCode accesstokens.DeviceCodeResult
}

func (f *AccessTokens) FromUsernamePassword(ctx context.Context, authParameters authority.AuthParams) (accesstokens.TokenResponse, error) {
	if f.Err {
		return accesstokens.TokenResponse{}, fmt.Errorf("error")
	}
	return f.AccessToken, nil
}
func (f *AccessTokens) FromAuthCode(ctx context.Context, req accesstokens.AuthCodeRequest) (accesstokens.TokenResponse, error) {
	if f.Err {
		return accesstokens.TokenResponse{}, fmt.Errorf("error")
	}
	return f.AccessToken, nil
}
func (f *AccessTokens) FromRefreshToken(ctx context.Context, appType accesstokens.AppType, authParams authority.AuthParams, cc *accesstokens.Credential, refreshToken string) (accesstokens.TokenResponse, error) {
	if f.Err {
		return accesstokens.TokenResponse{}, fmt.Errorf("error")
	}
	return f.AccessToken, nil
}
func (f *AccessTokens) FromClientSecret(ctx context.Context, authParameters authority.AuthParams, clientSecret string) (accesstokens.TokenResponse, error) {
	if f.Err {
		return accesstokens.TokenResponse{}, fmt.Errorf("error")
	}
	return f.AccessToken, nil
}
func (f *AccessTokens) FromAssertion(ctx context.Context, authParameters authority.AuthParams, assertion string) (accesstokens.TokenResponse, error) {
	if f.Err {
		return accesstokens.TokenResponse{}, fmt.Errorf("error")
	}
	return f.AccessToken, nil
}
func (f *AccessTokens) DeviceCodeResult(ctx context.Context, authParameters authority.AuthParams) (accesstokens.DeviceCodeResult, error) {
	if f.Err {
		return accesstokens.DeviceCodeResult{}, fmt.Errorf("error")
	}
	return f.DeviceCode, nil
}
func (f *AccessTokens) FromDeviceCodeResult(ctx context.Context, authParameters authority.AuthParams, deviceCodeResult accesstokens.DeviceCodeResult) (accesstokens.TokenResponse, error) {
	if f.Next < len(f.Result) {
		defer func() { f.Next++ }()
		v := f.Result[f.Next]
		if v == nil {
			return accesstokens.TokenResponse{ExpiresOn: internalTime.DurationTime{T: time.Now().Add(5 * time.Minute)}}, nil
		}
		return accesstokens.TokenResponse{}, v
	}
	panic("AccessTokens.FromDeviceCodeResult() asked for more return values than provided")
}
func (f *AccessTokens) FromSamlGrant(ctx context.Context, authParameters authority.AuthParams, samlGrant wstrust.SamlTokenInfo) (accesstokens.TokenResponse, error) {
	if f.Err {
		return accesstokens.TokenResponse{}, fmt.Errorf("error")
	}
	return f.AccessToken, nil
}

// Authority is a fake implementation of the oauth.fetchAuthority interface.
type Authority struct {
	// Set this to true to have all APIs return an error.
	Err bool

	// The fake UserRealm to return from the UserRealm() API.
	Realm authority.UserRealm

	// fake result to return
	InstanceResp authority.InstanceDiscoveryResponse
}

func (f Authority) UserRealm(ctx context.Context, params authority.AuthParams) (authority.UserRealm, error) {
	if f.Err {
		return authority.UserRealm{}, errors.New("error")
	}
	return f.Realm, nil
}

func (f Authority) AADInstanceDiscovery(ctx context.Context, info authority.Info) (authority.InstanceDiscoveryResponse, error) {
	if f.Err {
		return authority.InstanceDiscoveryResponse{}, errors.New("error")
	}
	return f.InstanceResp, nil
}

// WSTrust is a fake implementation of the oauth.fetchWSTrust interface.
type WSTrust struct {
	// Set these to true to have their respective APIs return an error.
	GetMexErr, GetSAMLTokenInfoErr bool

	// fake result to return
	MexDocument defs.MexDocument

	// fake result to return
	SamlTokenInfo wstrust.SamlTokenInfo
}

func (f WSTrust) Mex(ctx context.Context, federationMetadataURL string) (defs.MexDocument, error) {
	if f.GetMexErr {
		return defs.MexDocument{}, errors.New("error")
	}
	return f.MexDocument, nil
}

func (f WSTrust) SAMLTokenInfo(ctx context.Context, authParameters authority.AuthParams, cloudAudienceURN string, endpoint defs.Endpoint) (wstrust.SamlTokenInfo, error) {
	if f.GetSAMLTokenInfoErr {
		return wstrust.SamlTokenInfo{}, errors.New("error")
	}
	return f.SamlTokenInfo, nil
}
