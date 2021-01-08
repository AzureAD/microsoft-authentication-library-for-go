// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package oauth

// NOTE: These tests cover that we handle errors from other lower level modules.
// We don't actually care about a TokenResponse{}, that is gathered from a remote system
// and they are tested via intergration tests (data retrieved from one system and passed from
// to another). We care about execution behavior (service X says there is an error and we handle it,
// we require .X is set and input doesn't have it, ...)

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/wstrust"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/wstrust/defs"
)

type fakeResolveEndpoints struct {
	err bool
}

func (f fakeResolveEndpoints) ResolveEndpoints(ctx context.Context, authorityInfo authority.Info, userPrincipalName string) (authority.Endpoints, error) {
	if f.err {
		return authority.Endpoints{}, errors.New("error")
	}
	return authority.Endpoints{}, nil
}

type fakeAccessTokens struct {
	err bool

	// deviceCodeResult is for use with GetAccessTokenFromDeviceCodeResult. On each call it returns
	// the next item in this slice. They must be either an error or nil.
	deviceCodeResult []interface{}
	next             int
}

func (f *fakeAccessTokens) FromUsernamePassword(ctx context.Context, authParameters authority.AuthParams) (accesstokens.TokenResponse, error) {
	if f.err {
		return accesstokens.TokenResponse{}, fmt.Errorf("error")
	}
	return accesstokens.TokenResponse{}, nil
}
func (f *fakeAccessTokens) FromAuthCode(ctx context.Context, req accesstokens.AuthCodeRequest) (accesstokens.TokenResponse, error) {
	if f.err {
		return accesstokens.TokenResponse{}, fmt.Errorf("error")
	}
	return accesstokens.TokenResponse{}, nil
}
func (f *fakeAccessTokens) FromRefreshToken(ctx context.Context, rtType accesstokens.RefreshTokenReqType, authParams authority.AuthParams, cc *accesstokens.Credential, refreshToken string) (accesstokens.TokenResponse, error) {
	if f.err {
		return accesstokens.TokenResponse{}, fmt.Errorf("error")
	}
	return accesstokens.TokenResponse{}, nil
}
func (f *fakeAccessTokens) WithClientSecret(ctx context.Context, authParameters authority.AuthParams, clientSecret string) (accesstokens.TokenResponse, error) {
	if f.err {
		return accesstokens.TokenResponse{}, fmt.Errorf("error")
	}
	return accesstokens.TokenResponse{}, nil
}
func (f *fakeAccessTokens) WithAssertion(ctx context.Context, authParameters authority.AuthParams, assertion string) (accesstokens.TokenResponse, error) {
	if f.err {
		return accesstokens.TokenResponse{}, fmt.Errorf("error")
	}
	return accesstokens.TokenResponse{}, nil
}
func (f *fakeAccessTokens) DeviceCodeResult(ctx context.Context, authParameters authority.AuthParams) (accesstokens.DeviceCodeResult, error) {
	if f.err {
		return accesstokens.DeviceCodeResult{}, fmt.Errorf("error")
	}
	return accesstokens.DeviceCodeResult{}, nil
}
func (f *fakeAccessTokens) FromDeviceCodeResult(ctx context.Context, authParameters authority.AuthParams, deviceCodeResult accesstokens.DeviceCodeResult) (accesstokens.TokenResponse, error) {
	if f.next < len(f.deviceCodeResult) {
		defer func() { f.next++ }()
		v := f.deviceCodeResult[f.next]
		if v == nil {
			return accesstokens.TokenResponse{ExpiresOn: time.Now().Add(5 * time.Minute)}, nil
		}
		return accesstokens.TokenResponse{}, v.(error)
	}
	panic("fakeAccessTokens.GetAccessTokenFromDeviceCodeResult() asked for more return values than provided")
}
func (f *fakeAccessTokens) FromSamlGrant(ctx context.Context, authParameters authority.AuthParams, samlGrant wstrust.SamlTokenInfo) (accesstokens.TokenResponse, error) {
	if f.err {
		return accesstokens.TokenResponse{}, fmt.Errorf("error")
	}
	return accesstokens.TokenResponse{}, nil
}

type fakeAuthority struct {
	err       bool
	userRealm authority.UserRealm
}

func (f fakeAuthority) GetUserRealm(ctx context.Context, params authority.AuthParams) (authority.UserRealm, error) {
	if f.err {
		return authority.UserRealm{}, errors.New("error")
	}
	return f.userRealm, nil
}

func (f fakeAuthority) GetAadinstanceDiscoveryResponse(ctx context.Context, info authority.Info) (authority.InstanceDiscoveryResponse, error) {
	if f.err {
		return authority.InstanceDiscoveryResponse{}, errors.New("error")
	}
	return authority.InstanceDiscoveryResponse{}, nil
}

type fakeWSTrust struct {
	getMexErr, getSAMLTokenInfoErr bool
}

func (f fakeWSTrust) GetMex(ctx context.Context, federationMetadataURL string) (defs.MexDocument, error) {
	if f.getMexErr {
		return defs.MexDocument{}, errors.New("error")
	}
	return defs.MexDocument{}, nil
}

func (f fakeWSTrust) GetSAMLTokenInfo(ctx context.Context, authParameters authority.AuthParams, cloudAudienceURN string, endpoint defs.Endpoint) (wstrust.SamlTokenInfo, error) {
	if f.getSAMLTokenInfoErr {
		return wstrust.SamlTokenInfo{}, errors.New("error")
	}
	return wstrust.SamlTokenInfo{}, nil
}

func TestAuthCode(t *testing.T) {
	tests := []struct {
		desc string
		re   fakeResolveEndpoints
		at   *fakeAccessTokens
		err  bool
	}{
		{
			desc: "Error: Unable to resolve endpoints",
			re:   fakeResolveEndpoints{err: true},
			at:   &fakeAccessTokens{},
			err:  true,
		},
		{
			desc: "Error: REST access token error",
			re:   fakeResolveEndpoints{},
			at:   &fakeAccessTokens{err: true},
			err:  true,
		},
		{
			desc: "Success",
			re:   fakeResolveEndpoints{},
			at:   &fakeAccessTokens{},
		},
	}

	token := &Client{}
	for _, test := range tests {
		token.accessTokens = test.at
		token.resolver = test.re

		_, err := token.AuthCode(context.Background(), accesstokens.AuthCodeRequest{})
		switch {
		case err == nil && test.err:
			t.Errorf("TestAuthCode(%s): got err == nil, want err != nil", test.desc)
		case err != nil && !test.err:
			t.Errorf("TestAuthCode(%s): got err == %s, want err == nil", test.desc, err)
		}
	}
}

func TestCredential(t *testing.T) {
	tests := []struct {
		desc       string
		re         fakeResolveEndpoints
		at         *fakeAccessTokens
		authParams authority.AuthParams
		cred       *accesstokens.Credential
		err        bool
	}{
		{
			desc: "Error: Unable to resolve endpoints",
			re:   fakeResolveEndpoints{err: true},
			at:   &fakeAccessTokens{},
			cred: &accesstokens.Credential{
				Assertion: "assertion",
				Expires:   time.Now().Add(-5 * time.Minute),
			},
			err: true,
		},
		{
			desc: "Error: REST access token error on secret",
			re:   fakeResolveEndpoints{},
			at:   &fakeAccessTokens{err: true},
			cred: &accesstokens.Credential{
				Assertion: "assertion",
				Expires:   time.Now().Add(-5 * time.Minute),
			},
			err: true,
		},
		{
			desc: "Error: could not generate JWT from cred assertion",
			re:   fakeResolveEndpoints{},
			at:   &fakeAccessTokens{err: true},
			cred: &accesstokens.Credential{
				Assertion: "assertion",
				Expires:   time.Now().Add(5 * time.Minute),
				Cert:      &x509.Certificate{},
				// Key is nil and causes token.SignedString(c.Key) to fail in Credential.JWT()
			},
			err: true,
		},
		{
			desc: "Error: REST access token error on assertion",
			re:   fakeResolveEndpoints{},
			at:   &fakeAccessTokens{err: true},
			cred: &accesstokens.Credential{
				Assertion: "assertion",
				Expires:   time.Now().Add(-5 * time.Minute),
			},
			err: true,
		},
		{
			desc: "Success: secret cred",
			re:   fakeResolveEndpoints{},
			at:   &fakeAccessTokens{},
			cred: &accesstokens.Credential{
				Secret: "secret",
			},
		},
		{
			desc: "Success: assertion cred",
			re:   fakeResolveEndpoints{},
			at:   &fakeAccessTokens{},
			cred: &accesstokens.Credential{
				Assertion: "assertion",
				Expires:   time.Now().Add(-5 * time.Minute),
			},
		},
	}

	token := &Client{}
	for _, test := range tests {
		token.accessTokens = test.at
		token.resolver = test.re

		_, err := token.Credential(context.Background(), test.authParams, test.cred)
		switch {
		case err == nil && test.err:
			t.Errorf("TestCredential(%s): got err == nil, want err != nil", test.desc)
		case err != nil && !test.err:
			t.Errorf("TestCredential(%s): got err == %s, want err == nil", test.desc, err)
		}
	}
}

func TestRefresh(t *testing.T) {
	tests := []struct {
		desc string
		re   fakeResolveEndpoints
		at   *fakeAccessTokens
		err  bool
	}{
		{
			desc: "Error: Unable to resolve endpoints",
			re:   fakeResolveEndpoints{err: true},
			at:   &fakeAccessTokens{},
			err:  true,
		},
		{
			desc: "Error: REST access token error",
			re:   fakeResolveEndpoints{},
			at:   &fakeAccessTokens{err: true},
			err:  true,
		},
		{
			desc: "Success",
			re:   fakeResolveEndpoints{},
			at:   &fakeAccessTokens{},
		},
	}

	token := &Client{}
	for _, test := range tests {
		token.accessTokens = test.at
		token.resolver = test.re

		_, err := token.Refresh(
			context.Background(),
			accesstokens.RefreshTokenPublic,
			authority.AuthParams{},
			&accesstokens.Credential{},
			accesstokens.RefreshToken{},
		)
		switch {
		case err == nil && test.err:
			t.Errorf("TestRefresh(%s): got err == nil, want err != nil", test.desc)
		case err != nil && !test.err:
			t.Errorf("TestRefresh(%s): got err == %s, want err == nil", test.desc, err)
		}
	}
}

func TestUsernamePassword(t *testing.T) {
	tests := []struct {
		desc string
		re   fakeResolveEndpoints
		at   *fakeAccessTokens
		au   fakeAuthority
		ws   fakeWSTrust
		err  bool
	}{
		{
			desc: "Error: Unable to resolve endpoints",
			re:   fakeResolveEndpoints{err: true},
			at:   &fakeAccessTokens{},
			au:   fakeAuthority{userRealm: authority.UserRealm{AccountType: authority.Managed}},
			err:  true,
		},
		{
			desc: "Error: authority.Federated and GetMex() error",
			re:   fakeResolveEndpoints{err: false},
			at:   &fakeAccessTokens{},
			au:   fakeAuthority{userRealm: authority.UserRealm{AccountType: authority.Federated}},
			ws:   fakeWSTrust{getMexErr: true},
			err:  true,
		},
		{
			desc: "Error: authority.Federated and GetSAMLTokenInfo() error",
			re:   fakeResolveEndpoints{err: false},
			at:   &fakeAccessTokens{},
			au:   fakeAuthority{userRealm: authority.UserRealm{AccountType: authority.Federated}},
			ws:   fakeWSTrust{getSAMLTokenInfoErr: true},
			err:  true,
		},
		{
			desc: "Error: authority.Federated and GetAccessTokenFromSamlGrant() error",
			re:   fakeResolveEndpoints{err: false},
			au:   fakeAuthority{userRealm: authority.UserRealm{AccountType: authority.Federated}},
			at:   &fakeAccessTokens{err: true},
			err:  true,
		},
		{
			desc: "Error: authority.Managed and REST access token error",
			re:   fakeResolveEndpoints{err: false},
			at:   &fakeAccessTokens{err: true},
			au:   fakeAuthority{userRealm: authority.UserRealm{AccountType: authority.Managed}},
			err:  true,
		},
		{
			desc: "Success: authority.Managed",
			re:   fakeResolveEndpoints{err: false},
			at:   &fakeAccessTokens{},
			au:   fakeAuthority{userRealm: authority.UserRealm{AccountType: authority.Managed}},
		},
		{
			desc: "Success: authority.Federated",
			re:   fakeResolveEndpoints{err: false},
			at:   &fakeAccessTokens{},
			au:   fakeAuthority{userRealm: authority.UserRealm{AccountType: authority.Federated}},
		},
	}

	token := &Client{}
	for _, test := range tests {
		token.accessTokens = test.at
		token.authority = test.au
		token.resolver = test.re
		token.wsTrust = test.ws

		_, err := token.UsernamePassword(context.Background(), authority.AuthParams{})
		switch {
		case err == nil && test.err:
			t.Errorf("TestUsernamePassword(%s): got err == nil, want err != nil", test.desc)
		case err != nil && !test.err:
			t.Errorf("TestUsernamePassword(%s): got err == %s, want err == nil", test.desc, err)
		}
	}
}

func TestDeviceCode(t *testing.T) {
	tests := []struct {
		desc string
		dc   DeviceCode
		err  bool
	}{
		{
			desc: "Error: .accessTokens == nil",
			dc:   DeviceCode{},
			err:  true,
		},
		{
			desc: "Error: GetAccessTokenFromDeviceCodeResult() returned a !isWaitDeviceCodeErr",
			dc: DeviceCode{
				accessTokens: &fakeAccessTokens{
					deviceCodeResult: []interface{}{errors.New("authorization_pending"), errors.New("slow_down"), errors.New("bad error"), nil},
				},
			},
			err: true,
		},
		{
			desc: "Success",
			dc: DeviceCode{
				Result: accesstokens.DeviceCodeResult{
					ExpiresOn: time.Now().Add(5 * time.Minute),
				},
				accessTokens: &fakeAccessTokens{
					deviceCodeResult: []interface{}{errors.New("authorization_pending"), errors.New("slow_down"), nil},
				},
			},
		},
	}

	for _, test := range tests {
		_, err := test.dc.Token(context.Background())
		switch {
		case err == nil && test.err:
			t.Errorf("TestDeviceCode(%s): got err == nil, want err != nil", test.desc)
		case err != nil && !test.err:
			t.Errorf("TestDeviceCode(%s): got err == %s, want err == nil", test.desc, err)
		}
	}
}

func TestDeviceCodeToken(t *testing.T) {
	tests := []struct {
		desc string
		re   fakeResolveEndpoints
		at   *fakeAccessTokens
		err  bool
	}{
		{
			desc: "Error: Unable to resolve endpoints",
			re:   fakeResolveEndpoints{err: true},
			at:   &fakeAccessTokens{},
			err:  true,
		},
		{
			desc: "Error: REST access token error",
			re:   fakeResolveEndpoints{},
			at:   &fakeAccessTokens{err: true},
			err:  true,
		},
		{
			desc: "Success",
			re:   fakeResolveEndpoints{},
			at:   &fakeAccessTokens{},
		},
	}

	token := &Client{}
	for _, test := range tests {
		token.accessTokens = test.at
		token.resolver = test.re

		dc, err := token.DeviceCode(context.Background(), authority.AuthParams{})
		switch {
		case err == nil && test.err:
			t.Errorf("TestDeviceCodeToken(%s): got err == nil, want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestDeviceCodeToken(%s): got err == %s, want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if dc.accessTokens == nil {
			t.Errorf("TestDeviceCodeToken(%s): got DeviceCode{} back that did not have accessTokens set", test.desc)
		}
	}
}
